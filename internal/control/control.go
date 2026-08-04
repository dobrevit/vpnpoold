package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dobrevit/vpnpoold/internal/proxy/dispatcher"
	"github.com/dobrevit/vpnpoold/internal/worker"
)

const (
	maxRequestBytes = 4096
	socketMode      = 0o600
)

type SnapshotFunc func() []worker.Snapshot
type DispatcherStatsFunc func() dispatcher.Stats

type WorkerActions interface {
	SetWorkerEnabled(context.Context, string, bool) error
	SetWorkerDraining(context.Context, string, bool) error
	RestartWorker(context.Context, string) error
	Reload(context.Context) error
}

type WorkerStatus struct {
	ID                   string     `json:"id"`
	State                string     `json:"state"`
	StateSince           time.Time  `json:"state_since"`
	Reason               string     `json:"reason,omitempty"`
	Enabled              bool       `json:"enabled"`
	Draining             bool       `json:"draining"`
	Available            bool       `json:"available"`
	PublicIP             string     `json:"public_ip,omitempty"`
	ExpectedIPConfigured bool       `json:"expected_ip_configured"`
	ExpectedIPVerified   bool       `json:"expected_ip_verified"`
	UniquenessEnforced   bool       `json:"uniqueness_enforced"`
	PublicIPUnique       bool       `json:"public_ip_unique"`
	LastHealthyAt        *time.Time `json:"last_healthy_at,omitempty"`
	ActiveConnections    int64      `json:"active_connections"`
	ConnectionsTotal     uint64     `json:"connections_total"`
	BackendSelections    uint64     `json:"backend_selections_total"`
	BytesFromClients     uint64     `json:"bytes_from_clients_total"`
	BytesToClients       uint64     `json:"bytes_to_clients_total"`
	OpenVPNRestarts      uint64     `json:"openvpn_restarts_total"`
	ProxyRestarts        uint64     `json:"proxy_restarts_total"`
	HealthCheckSuccesses uint64     `json:"healthcheck_successes_total"`
	HealthCheckFailures  uint64     `json:"healthcheck_failures_total"`
}

type DispatcherStatus struct {
	ActiveConnections      int64  `json:"active_connections"`
	ConnectionsTotal       uint64 `json:"connections_total"`
	AuthenticationFailures uint64 `json:"authentication_failures_total"`
	BackendSelections      uint64 `json:"backend_selections_total"`
	BackendRetries         uint64 `json:"backend_retries_total"`
	NoWorkerFailures       uint64 `json:"no_worker_failures_total"`
	BytesFromClients       uint64 `json:"bytes_from_clients_total"`
	BytesToClients         uint64 `json:"bytes_to_clients_total"`
}

type StatusResponse struct {
	Workers    []WorkerStatus   `json:"workers"`
	Dispatcher DispatcherStatus `json:"dispatcher"`
}

type request struct {
	Operation string `json:"operation"`
	WorkerID  string `json:"worker_id,omitempty"`
}

type response struct {
	Status *StatusResponse `json:"status,omitempty"`
	OK     bool            `json:"ok,omitempty"`
	Error  string          `json:"error,omitempty"`
}

type Server struct {
	socketPath string
	snapshots  SnapshotFunc
	stats      DispatcherStatsFunc
	actions    WorkerActions
	logger     *slog.Logger
	wait       sync.WaitGroup
}

func NewServer(
	socketPath string,
	snapshots SnapshotFunc,
	actions WorkerActions,
	logger *slog.Logger,
) (*Server, error) {
	return NewServerWithStats(socketPath, snapshots, nil, actions, logger)
}

func NewServerWithStats(
	socketPath string,
	snapshots SnapshotFunc,
	stats DispatcherStatsFunc,
	actions WorkerActions,
	logger *slog.Logger,
) (*Server, error) {
	if !filepath.IsAbs(socketPath) {
		return nil, errors.New("control socket path must be absolute")
	}
	if len(socketPath) > 100 {
		return nil, errors.New("control socket path is too long")
	}
	if snapshots == nil {
		return nil, errors.New("worker snapshot function is required")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Server{
		socketPath: socketPath, snapshots: snapshots, stats: stats,
		actions: actions, logger: logger,
	}, nil
}

func (s *Server) Listen() (*net.UnixListener, error) {
	if err := validateSocketDirectory(filepath.Dir(s.socketPath)); err != nil {
		return nil, err
	}
	if err := removeStaleSocket(s.socketPath); err != nil {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.socketPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen on control socket: %w", err)
	}
	if err := os.Chmod(s.socketPath, socketMode); err != nil {
		_ = listener.Close()
		_ = os.Remove(s.socketPath)
		return nil, fmt.Errorf("restrict control socket permissions: %w", err)
	}
	return listener, nil
}

func (s *Server) Serve(ctx context.Context, listener *net.UnixListener) error {
	if ctx == nil || listener == nil {
		return errors.New("control context and listener are required")
	}
	defer os.Remove(s.socketPath)
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stop:
		}
	}()
	defer close(stop)

	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				s.wait.Wait()
				return nil
			}
			s.wait.Wait()
			return fmt.Errorf("accept control connection: %w", err)
		}
		if err := authorizePeer(connection); err != nil {
			_ = connection.Close()
			s.logger.Debug("rejected unauthorized control peer")
			continue
		}
		s.wait.Add(1)
		go func() {
			defer s.wait.Done()
			defer connection.Close()
			if err := s.serveConnection(ctx, connection); err != nil {
				s.logger.Debug("control request failed")
			}
		}()
	}
}

func validateSocketDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect control socket directory: %w", err)
	}
	if !info.IsDir() {
		return errors.New("control socket directory must be a directory, not a symbolic link")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("control socket directory must not be accessible by group or other users")
	}
	return nil
}

func authorizePeer(connection *net.UnixConn) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return errors.New("inspect control peer")
	}
	var credentials *syscall.Ucred
	var socketErr error
	if err := raw.Control(func(descriptor uintptr) {
		credentials, socketErr = syscall.GetsockoptUcred(
			int(descriptor), syscall.SOL_SOCKET, syscall.SO_PEERCRED,
		)
	}); err != nil || socketErr != nil || credentials == nil {
		return errors.New("inspect control peer credentials")
	}
	if credentials.Uid != uint32(os.Geteuid()) {
		return errors.New("control peer does not match daemon user")
	}
	return nil
}

func (s *Server) serveConnection(parent context.Context, connection net.Conn) error {
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	reader := bufio.NewReader(io.LimitReader(connection, maxRequestBytes+1))
	line, err := reader.ReadString('\n')
	if err != nil {
		return writeResponse(connection, response{Error: "invalid request"})
	}
	if len(line) > maxRequestBytes {
		return writeResponse(connection, response{Error: "request is too large"})
	}
	var input request
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return writeResponse(connection, response{Error: "invalid request"})
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return writeResponse(connection, response{Error: "invalid request"})
	}
	switch input.Operation {
	case "status":
		if input.WorkerID != "" {
			return writeResponse(connection, response{Error: "status does not accept worker_id"})
		}
		var stats dispatcher.Stats
		if s.stats != nil {
			stats = s.stats()
		}
		status := statusFromSnapshots(s.snapshots(), stats)
		return writeResponse(connection, response{Status: &status})
	case "enable", "disable", "drain", "undrain", "restart":
		if s.actions == nil {
			return writeResponse(connection, response{Error: "worker actions are unavailable"})
		}
		if input.WorkerID == "" {
			return writeResponse(connection, response{Error: "worker_id is required"})
		}
		actionContext, cancel := context.WithTimeout(parent, 5*time.Second)
		defer cancel()
		var actionErr error
		switch input.Operation {
		case "enable":
			actionErr = s.actions.SetWorkerEnabled(actionContext, input.WorkerID, true)
		case "disable":
			actionErr = s.actions.SetWorkerEnabled(actionContext, input.WorkerID, false)
		case "drain":
			actionErr = s.actions.SetWorkerDraining(actionContext, input.WorkerID, true)
		case "undrain":
			actionErr = s.actions.SetWorkerDraining(actionContext, input.WorkerID, false)
		case "restart":
			actionErr = s.actions.RestartWorker(actionContext, input.WorkerID)
		}
		if actionErr != nil {
			return writeResponse(connection, response{Error: actionErr.Error()})
		}
		return writeResponse(connection, response{OK: true})
	case "reload":
		if input.WorkerID != "" {
			return writeResponse(connection, response{Error: "reload does not accept worker_id"})
		}
		if s.actions == nil {
			return writeResponse(connection, response{Error: "reload is unavailable"})
		}
		actionContext, cancel := context.WithTimeout(parent, 5*time.Second)
		defer cancel()
		if err := s.actions.Reload(actionContext); err != nil {
			return writeResponse(connection, response{Error: err.Error()})
		}
		return writeResponse(connection, response{OK: true})
	default:
		return writeResponse(connection, response{Error: "unsupported operation"})
	}
}

func statusFromSnapshots(snapshots []worker.Snapshot, stats dispatcher.Stats) StatusResponse {
	result := StatusResponse{
		Workers: make([]WorkerStatus, 0, len(snapshots)),
		Dispatcher: DispatcherStatus{
			ActiveConnections:      stats.ActiveConnections,
			ConnectionsTotal:       stats.ConnectionsTotal,
			AuthenticationFailures: stats.AuthenticationFailures,
			BackendSelections:      stats.BackendSelections,
			BackendRetries:         stats.BackendRetries,
			NoWorkerFailures:       stats.NoWorkerFailures,
			BytesFromClients:       stats.BytesFromClients,
			BytesToClients:         stats.BytesToClients,
		},
	}
	for _, snapshot := range snapshots {
		publicIP := ""
		if snapshot.Evidence.PublicIP.IsValid() {
			publicIP = snapshot.Evidence.PublicIP.String()
		}
		var lastHealthyAt *time.Time
		if !snapshot.LastHealthyAt.IsZero() {
			value := snapshot.LastHealthyAt
			lastHealthyAt = &value
		}
		result.Workers = append(result.Workers, WorkerStatus{
			ID: snapshot.ID, State: snapshot.State.String(),
			StateSince: snapshot.StateSince, Reason: snapshot.Reason,
			Enabled: snapshot.Enabled, Draining: snapshot.Draining,
			Available:            snapshot.Available,
			PublicIP:             publicIP,
			ExpectedIPConfigured: snapshot.Evidence.ExpectedIPConfigured,
			ExpectedIPVerified: snapshot.Evidence.ExpectedIPChecked &&
				snapshot.Evidence.ExpectedIPMatches,
			UniquenessEnforced: snapshot.Evidence.UniquenessEnforced,
			PublicIPUnique: snapshot.Evidence.UniquenessChecked &&
				snapshot.Evidence.PublicIPUnique,
			LastHealthyAt:        lastHealthyAt,
			ActiveConnections:    snapshot.ActiveConnections,
			ConnectionsTotal:     snapshot.ConnectionsTotal,
			BackendSelections:    snapshot.BackendSelections,
			BytesFromClients:     snapshot.BytesFromClients,
			BytesToClients:       snapshot.BytesToClients,
			OpenVPNRestarts:      snapshot.OpenVPNRestarts,
			ProxyRestarts:        snapshot.ProxyRestarts,
			HealthCheckSuccesses: snapshot.HealthCheckSuccesses,
			HealthCheckFailures:  snapshot.HealthCheckFailures,
		})
	}
	return result
}

func Status(ctx context.Context, socketPath string) (StatusResponse, error) {
	output, err := requestControl(ctx, socketPath, request{Operation: "status"})
	if err != nil {
		return StatusResponse{}, err
	}
	if output.Status == nil {
		return StatusResponse{}, errors.New("daemon returned no status")
	}
	return *output.Status, nil
}

func WorkerAction(ctx context.Context, socketPath, operation, workerID string) error {
	switch operation {
	case "enable", "disable", "drain", "undrain", "restart":
	default:
		return errors.New("worker action is unsupported")
	}
	if workerID == "" {
		return errors.New("worker ID is required")
	}
	output, err := requestControl(ctx, socketPath, request{
		Operation: operation, WorkerID: workerID,
	})
	if err != nil {
		return err
	}
	if !output.OK {
		return errors.New("daemon did not acknowledge worker action")
	}
	return nil
}

func Reload(ctx context.Context, socketPath string) error {
	output, err := requestControl(ctx, socketPath, request{Operation: "reload"})
	if err != nil {
		return err
	}
	if !output.OK {
		return errors.New("daemon did not acknowledge reload")
	}
	return nil
}

func requestControl(ctx context.Context, socketPath string, input request) (response, error) {
	if !filepath.IsAbs(socketPath) {
		return response{}, errors.New("control socket path must be absolute")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		return response{}, fmt.Errorf("connect to daemon control socket: %w", err)
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return response{}, err
		}
	}
	if err := json.NewEncoder(connection).Encode(input); err != nil {
		return response{}, fmt.Errorf("request daemon control operation: %w", err)
	}
	var output response
	if err := json.NewDecoder(io.LimitReader(connection, 1024*1024)).Decode(&output); err != nil {
		return response{}, fmt.Errorf("decode daemon control response: %w", err)
	}
	if output.Error != "" {
		return response{}, errors.New(output.Error)
	}
	return output, nil
}

func writeResponse(writer io.Writer, value response) error {
	return json.NewEncoder(writer).Encode(value)
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect control socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("refusing to replace a non-socket control path")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale control socket: %w", err)
	}
	return nil
}

package metrics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dobrevit/vpnpoold/internal/proxy/dispatcher"
	"github.com/dobrevit/vpnpoold/internal/worker"
)

type WorkerSnapshots func() []worker.Snapshot
type DispatcherStats func() dispatcher.Stats

type Server struct {
	handler http.Handler
}

func NewServer(snapshots WorkerSnapshots, stats DispatcherStats) (*Server, error) {
	if snapshots == nil || stats == nil {
		return nil, errors.New("metrics snapshot and dispatcher statistics functions are required")
	}
	return &Server{handler: handler{snapshots: snapshots, stats: stats}}, nil
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if ctx == nil || listener == nil {
		return errors.New("metrics context and listener are required")
	}
	httpServer := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = httpServer.Close()
		case <-done:
		}
	}()
	err := httpServer.Serve(listener)
	close(done)
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		return nil
	}
	return err
}

type handler struct {
	snapshots WorkerSnapshots
	stats     DispatcherStats
}

func (h handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/metrics" {
		http.NotFound(response, request)
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		response.Header().Set("Allow", "GET, HEAD")
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	response.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	if request.Method == http.MethodHead {
		response.WriteHeader(http.StatusOK)
		return
	}
	writeMetrics(response, h.snapshots(), h.stats())
}

func writeMetrics(output io.Writer, snapshots []worker.Snapshot, stats dispatcher.Stats) {
	snapshots = append([]worker.Snapshot(nil), snapshots...)
	sort.Slice(snapshots, func(i, j int) bool { return snapshots[i].ID < snapshots[j].ID })

	writeType(output, "vpnpool_worker_healthy", "gauge",
		"Whether a worker has complete health evidence and is available.")
	for _, snapshot := range snapshots {
		writeWorkerMetric(output, "vpnpool_worker_healthy", snapshot.ID, boolFloat(snapshot.Available))
	}
	writeType(output, "vpnpool_worker_enabled", "gauge",
		"Whether a worker is enabled for lifecycle supervision.")
	for _, snapshot := range snapshots {
		writeWorkerMetric(output, "vpnpool_worker_enabled", snapshot.ID, boolFloat(snapshot.Enabled))
	}
	writeType(output, "vpnpool_worker_draining", "gauge",
		"Whether a worker is excluded from new assignments by operator drain.")
	for _, snapshot := range snapshots {
		writeWorkerMetric(output, "vpnpool_worker_draining", snapshot.ID, boolFloat(snapshot.Draining))
	}
	writeType(output, "vpnpool_worker_state", "gauge",
		"The current worker lifecycle state.")
	for _, snapshot := range snapshots {
		fmt.Fprintf(output, "vpnpool_worker_state{worker=%s,state=%s} 1\n",
			quoteLabel(snapshot.ID), quoteLabel(snapshot.State.String()))
	}
	writeType(output, "vpnpool_worker_state_since_timestamp_seconds", "gauge",
		"Unix timestamp when the worker entered its current state.")
	for _, snapshot := range snapshots {
		writeWorkerMetric(output, "vpnpool_worker_state_since_timestamp_seconds",
			snapshot.ID, timestamp(snapshot.StateSince))
	}
	writeType(output, "vpnpool_worker_last_healthy_timestamp_seconds", "gauge",
		"Unix timestamp when the worker most recently completed egress verification.")
	for _, snapshot := range snapshots {
		writeWorkerMetric(output, "vpnpool_worker_last_healthy_timestamp_seconds",
			snapshot.ID, timestamp(snapshot.LastHealthyAt))
	}

	workerMetrics := []struct {
		name string
		kind string
		help string
		get  func(worker.Snapshot) float64
	}{
		{
			"vpnpool_worker_active_connections", "gauge",
			"Current dispatcher connections assigned to a worker.",
			func(snapshot worker.Snapshot) float64 { return float64(snapshot.ActiveConnections) },
		},
		{
			"vpnpool_worker_connections_total", "counter",
			"Dispatcher connections established through a worker.",
			func(snapshot worker.Snapshot) float64 { return float64(snapshot.ConnectionsTotal) },
		},
		{
			"vpnpool_worker_backend_selections_total", "counter",
			"Dispatcher connection attempts assigned to a worker.",
			func(snapshot worker.Snapshot) float64 { return float64(snapshot.BackendSelections) },
		},
		{
			"vpnpool_worker_bytes_rx_total", "counter",
			"Bytes received from clients and sent through a worker.",
			func(snapshot worker.Snapshot) float64 { return float64(snapshot.BytesFromClients) },
		},
		{
			"vpnpool_worker_bytes_tx_total", "counter",
			"Bytes received through a worker and sent to clients.",
			func(snapshot worker.Snapshot) float64 { return float64(snapshot.BytesToClients) },
		},
		{
			"vpnpool_worker_openvpn_restarts_total", "counter",
			"OpenVPN recovery cycles observed for a worker.",
			func(snapshot worker.Snapshot) float64 { return float64(snapshot.OpenVPNRestarts) },
		},
		{
			"vpnpool_worker_proxy_restarts_total", "counter",
			"Worker proxy recovery cycles scheduled for a worker.",
			func(snapshot worker.Snapshot) float64 { return float64(snapshot.ProxyRestarts) },
		},
		{
			"vpnpool_worker_healthcheck_successes_total", "counter",
			"Successful worker egress verification checks.",
			func(snapshot worker.Snapshot) float64 { return float64(snapshot.HealthCheckSuccesses) },
		},
		{
			"vpnpool_worker_healthcheck_failures_total", "counter",
			"Failed worker egress verification checks.",
			func(snapshot worker.Snapshot) float64 { return float64(snapshot.HealthCheckFailures) },
		},
	}
	for _, metric := range workerMetrics {
		writeType(output, metric.name, metric.kind, metric.help)
		for _, snapshot := range snapshots {
			writeWorkerMetric(output, metric.name, snapshot.ID, metric.get(snapshot))
		}
	}

	dispatcherMetrics := []struct {
		name  string
		kind  string
		help  string
		value float64
	}{
		{"vpnpool_dispatcher_active_connections", "gauge",
			"Current client connections accepted by the dispatcher.", float64(stats.ActiveConnections)},
		{"vpnpool_dispatcher_connections_total", "counter",
			"Client connections accepted by the dispatcher.", float64(stats.ConnectionsTotal)},
		{"vpnpool_dispatcher_authentication_failures_total", "counter",
			"Rejected dispatcher authentication attempts.", float64(stats.AuthenticationFailures)},
		{"vpnpool_dispatcher_selection_total", "counter",
			"Worker selections made by the dispatcher.", float64(stats.BackendSelections)},
		{"vpnpool_dispatcher_retries_total", "counter",
			"Pre-acknowledgement worker retries made by the dispatcher.", float64(stats.BackendRetries)},
		{"vpnpool_dispatcher_no_worker_failures_total", "counter",
			"Connections rejected because no worker was available.", float64(stats.NoWorkerFailures)},
		{"vpnpool_dispatcher_bytes_rx_total", "counter",
			"Bytes received by the dispatcher from clients.", float64(stats.BytesFromClients)},
		{"vpnpool_dispatcher_bytes_tx_total", "counter",
			"Bytes sent by the dispatcher to clients.", float64(stats.BytesToClients)},
	}
	for _, metric := range dispatcherMetrics {
		writeType(output, metric.name, metric.kind, metric.help)
		fmt.Fprintf(output, "%s %s\n", metric.name, formatFloat(metric.value))
	}
}

func writeType(output io.Writer, name, kind, help string) {
	fmt.Fprintf(output, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
}

func writeWorkerMetric(output io.Writer, name, workerID string, value float64) {
	fmt.Fprintf(output, "%s{worker=%s} %s\n", name, quoteLabel(workerID), formatFloat(value))
}

func quoteLabel(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\"", "\\\"")
	return `"` + replacer.Replace(value) + `"`
}

func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func boolFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func timestamp(value time.Time) float64 {
	if value.IsZero() {
		return 0
	}
	return float64(value.UnixNano()) / float64(time.Second)
}

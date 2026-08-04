package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/dobrevit/vpnpoold/internal/netutil"
	"github.com/dobrevit/vpnpoold/internal/process"
)

type WorkerProxyLauncher struct {
	Starter           process.Starter
	Readiness         ProxyReadiness
	IPBinary          string
	DaemonBinary      string
	Namespace         string
	WorkerID          string
	ListenAddress     string
	UpstreamHTTPProxy string
	HandshakeTimeout  time.Duration
	ConnectTimeout    time.Duration
	IdleTimeout       time.Duration
	AllowIPv6         bool
	LogFormat         string
	LogLevel          string
}

func (l WorkerProxyLauncher) Start(ctx context.Context) (process.ManagedProcess, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}
	args := []string{
		"netns", "exec", l.Namespace,
		l.DaemonBinary,
		"worker-proxy",
		"--worker-id", l.WorkerID,
		"--listen", l.ListenAddress,
		"--handshake-timeout", l.HandshakeTimeout.String(),
		"--connect-timeout", l.ConnectTimeout.String(),
		"--idle-timeout", l.IdleTimeout.String(),
		"--log-format", l.LogFormat,
		"--log-level", l.LogLevel,
	}
	if l.AllowIPv6 {
		args = append(args, "--allow-ipv6")
	}
	if l.UpstreamHTTPProxy != "" {
		args = append(args, "--upstream-http-proxy", l.UpstreamHTTPProxy)
	}
	running, err := l.Starter.Start(ctx, process.Command{
		Path: l.IPBinary,
		Args: args,
		Env:  []string{"LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"},
	})
	if err != nil {
		return nil, fmt.Errorf("start worker %q namespace proxy: %w", l.WorkerID, err)
	}
	if running == nil {
		return nil, fmt.Errorf("start worker %q namespace proxy: starter returned no process", l.WorkerID)
	}
	if err := l.Readiness.Wait(ctx, l.ListenAddress); err != nil {
		stopErr := stopUnreadyProxy(running, 2*time.Second)
		return nil, errors.Join(
			fmt.Errorf("wait for worker %q namespace proxy readiness: %w", l.WorkerID, err),
			stopErr,
		)
	}
	return running, nil
}

func (l WorkerProxyLauncher) validate() error {
	if l.Starter == nil {
		return errors.New("process starter is required")
	}
	if l.Readiness == nil {
		return errors.New("proxy readiness probe is required")
	}
	if !filepath.IsAbs(l.IPBinary) || !filepath.IsAbs(l.DaemonBinary) {
		return errors.New("ip and daemon binary paths must be absolute")
	}
	if !netutil.IsValidNamespaceName(l.Namespace) {
		return errors.New("namespace name is invalid")
	}
	if !netutil.IsValidWorkerID(l.WorkerID) {
		return errors.New("worker ID is invalid")
	}
	host, portText, err := net.SplitHostPort(l.ListenAddress)
	if err != nil {
		return errors.New("worker proxy listen address is invalid")
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.IsUnspecified() || address.IsLoopback() {
		return errors.New("worker proxy must listen on an explicit namespace veth address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("worker proxy port is invalid")
	}
	if l.HandshakeTimeout <= 0 || l.ConnectTimeout <= 0 || l.IdleTimeout <= 0 {
		return errors.New("worker proxy timeouts must be positive")
	}
	if l.UpstreamHTTPProxy != "" {
		host, portText, splitErr := net.SplitHostPort(l.UpstreamHTTPProxy)
		address, addressErr := netip.ParseAddr(host)
		port, portErr := strconv.Atoi(portText)
		if splitErr != nil ||
			addressErr != nil ||
			!address.Is4() ||
			address.IsUnspecified() ||
			address.IsLoopback() ||
			address.IsMulticast() ||
			portErr != nil ||
			port < 1 ||
			port > 65535 {
			return errors.New("upstream HTTP proxy must be an explicit IPv4 address and TCP port")
		}
	}
	if l.LogFormat != "json" && l.LogFormat != "text" {
		return errors.New("worker proxy log format is invalid")
	}
	switch l.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return errors.New("worker proxy log level is invalid")
	}
	return nil
}

type ProxyReadiness interface {
	Wait(context.Context, string) error
}

type ReadinessDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type TCPProxyReadiness struct {
	Dialer   ReadinessDialer
	Timeout  time.Duration
	Interval time.Duration
}

func (p TCPProxyReadiness) Wait(parent context.Context, address string) error {
	if parent == nil {
		return errors.New("proxy readiness context is required")
	}
	if p.Timeout <= 0 || p.Interval <= 0 {
		return errors.New("proxy readiness timeout and interval must be positive")
	}
	dialer := p.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	ctx, cancel := context.WithTimeout(parent, p.Timeout)
	defer cancel()
	for {
		connection, err := dialer.DialContext(ctx, "tcp4", address)
		if err == nil {
			if closeErr := connection.Close(); closeErr != nil {
				return fmt.Errorf("close proxy readiness connection: %w", closeErr)
			}
			return nil
		}
		timer := time.NewTimer(p.Interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return fmt.Errorf("proxy listener did not become ready: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

func stopUnreadyProxy(running process.ManagedProcess, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		done <- running.Wait()
	}()
	signalErr := running.Signal(syscall.SIGTERM)
	if signalErr != nil && !errors.Is(signalErr, os.ErrProcessDone) {
		_ = running.Kill()
		return fmt.Errorf("signal unready proxy process: %w", signalErr)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		if err := running.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("kill unready proxy process: %w", err)
		}
		select {
		case <-done:
			return nil
		case <-time.After(timeout):
			return errors.New("unready proxy process did not exit after forced termination")
		}
	}
}

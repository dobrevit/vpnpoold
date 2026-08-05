package controller

import (
	"context"
	"errors"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dobrevit/vpnpoold/internal/process"
)

func TestWorkerProxyLauncherUsesDirectNamespaceCommand(t *testing.T) {
	starter := &launcherStarter{process: launcherProcess{}}
	launcher := WorkerProxyLauncher{
		Starter:           starter,
		Readiness:         immediateReadiness{},
		IPBinary:          "/usr/sbin/ip",
		DaemonBinary:      "/usr/local/sbin/vpnpoold",
		Namespace:         "vpnpool-1234567890",
		WorkerID:          "worker-1",
		ListenAddress:     "10.231.0.2:1081",
		AllowedClient:     "10.231.0.1",
		UpstreamHTTPProxy: "192.168.1.1:3128",
		HandshakeTimeout:  10 * time.Second,
		ConnectTimeout:    15 * time.Second,
		IdleTimeout:       5 * time.Minute,
		AllowIPv6:         true,
		LogFormat:         "json",
		LogLevel:          "info",
	}
	if _, err := launcher.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	want := process.Command{
		Path: "/usr/sbin/ip",
		Env:  []string{"LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"},
		Args: []string{
			"netns", "exec", "vpnpool-1234567890",
			"/usr/local/sbin/vpnpoold",
			"worker-proxy",
			"--worker-id", "worker-1",
			"--listen", "10.231.0.2:1081",
			"--allowed-client", "10.231.0.1",
			"--handshake-timeout", "10s",
			"--connect-timeout", "15s",
			"--idle-timeout", "5m0s",
			"--log-format", "json",
			"--log-level", "info",
			"--allow-ipv6",
			"--upstream-http-proxy", "192.168.1.1:3128",
		},
	}
	if !reflect.DeepEqual(starter.command, want) {
		t.Fatalf("command = %#v, want %#v", starter.command, want)
	}
}

func TestWorkerProxyLauncherRejectsInvalidUpstreamProxy(t *testing.T) {
	launcher := WorkerProxyLauncher{
		Starter:           &launcherStarter{},
		IPBinary:          "/usr/sbin/ip",
		DaemonBinary:      "/usr/local/sbin/vpnpoold",
		Namespace:         "vpnpool-1234567890",
		WorkerID:          "worker-1",
		ListenAddress:     "10.231.0.2:1081",
		AllowedClient:     "10.231.0.1",
		UpstreamHTTPProxy: "proxy.example:3128",
		HandshakeTimeout:  time.Second,
		ConnectTimeout:    time.Second,
		IdleTimeout:       time.Second,
		LogFormat:         "json",
		LogLevel:          "info",
	}
	if _, err := launcher.Start(context.Background()); err == nil {
		t.Fatal("Start() unexpectedly accepted an upstream proxy hostname")
	}
}

func TestWorkerProxyLauncherRejectsWildcardListener(t *testing.T) {
	launcher := WorkerProxyLauncher{
		Starter:          &launcherStarter{},
		IPBinary:         "/usr/sbin/ip",
		DaemonBinary:     "/usr/local/sbin/vpnpoold",
		Namespace:        "vpnpool-1234567890",
		WorkerID:         "worker-1",
		ListenAddress:    "0.0.0.0:1081",
		AllowedClient:    "10.231.0.1",
		HandshakeTimeout: time.Second,
		ConnectTimeout:   time.Second,
		IdleTimeout:      time.Second,
		LogFormat:        "json",
		LogLevel:         "info",
	}
	if _, err := launcher.Start(context.Background()); err == nil {
		t.Fatal("Start() unexpectedly accepted wildcard listener")
	}
}

func TestTCPProxyReadinessRetriesUntilListenerAccepts(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	dialer := &readinessSequenceDialer{
		failures:   2,
		connection: client,
	}
	probe := TCPProxyReadiness{
		Dialer:   dialer,
		Timeout:  time.Second,
		Interval: time.Millisecond,
	}
	if err := probe.Wait(context.Background(), "10.231.0.2:1081"); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if dialer.calls != 3 {
		t.Fatalf("dial calls = %d, want 3", dialer.calls)
	}
}

func TestTCPProxyReadinessTimesOut(t *testing.T) {
	probe := TCPProxyReadiness{
		Dialer:   &readinessSequenceDialer{failures: 100},
		Timeout:  5 * time.Millisecond,
		Interval: time.Millisecond,
	}
	err := probe.Wait(context.Background(), "10.231.0.2:1081")
	if err == nil || !strings.Contains(err.Error(), "did not become ready") {
		t.Fatalf("Wait() error = %v", err)
	}
}

type launcherStarter struct {
	command process.Command
	process process.ManagedProcess
}

func (s *launcherStarter) Start(_ context.Context, command process.Command) (process.ManagedProcess, error) {
	s.command = command
	return s.process, nil
}

type launcherProcess struct{}

func (launcherProcess) PID() int               { return 123 }
func (launcherProcess) Wait() error            { return nil }
func (launcherProcess) Signal(os.Signal) error { return nil }
func (launcherProcess) Kill() error            { return nil }

type immediateReadiness struct{}

func (immediateReadiness) Wait(context.Context, string) error {
	return nil
}

type readinessSequenceDialer struct {
	mu         sync.Mutex
	failures   int
	calls      int
	connection net.Conn
}

func (d *readinessSequenceDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	if d.calls <= d.failures {
		return nil, errors.New("listener not ready")
	}
	if d.connection == nil {
		return nil, errors.New("no connection configured")
	}
	return d.connection, nil
}

package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dobrevit/vpnpoold/internal/balance"
	"github.com/dobrevit/vpnpoold/internal/control"
	"github.com/dobrevit/vpnpoold/internal/firewall"
	"github.com/dobrevit/vpnpoold/internal/health"
	"github.com/dobrevit/vpnpoold/internal/netutil"
	"github.com/dobrevit/vpnpoold/internal/proxy/dispatcher"
	"github.com/dobrevit/vpnpoold/internal/worker"
)

func privateTempDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestRuntimeOrdersCleanupFirewallListenerAndShutdown(t *testing.T) {
	var orderMu sync.Mutex
	var order []string
	record := func(value string) {
		orderMu.Lock()
		defer orderMu.Unlock()
		order = append(order, value)
	}
	cleaner := &recordingCleaner{record: record}
	hostFirewall := &recordingHostFirewall{record: record}
	front := testDispatcher(t)
	model, err := worker.NewModel("worker-1")
	if err != nil {
		t.Fatal(err)
	}
	allocation := netutil.Allocation{WorkerID: "worker-1"}
	workerStarted := make(chan struct{}, 2)
	runDirectory := privateTempDir(t)
	generationDirectory, err := os.MkdirTemp(runDirectory, "generation-")
	if err != nil {
		t.Fatal(err)
	}
	controlServer, err := control.NewServer(
		filepath.Join(runDirectory, "control.sock"),
		func() []worker.Snapshot { return []worker.Snapshot{model.Snapshot()} },
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{
		workers: []controlledWorker{{
			id: "worker-1", model: model, allocation: allocation,
			run: func(ctx context.Context) error {
				record("worker")
				workerStarted <- struct{}{}
				<-ctx.Done()
				return nil
			},
		}},
		namespace: cleaner, cleanupStale: true,
		dispatcher: front, control: controlServer, firewall: hostFirewall,
		hostRules: firewall.HostRules{}, listenAddress: "127.0.0.1:0",
		runDirectory: runDirectory, generationDirectory: generationDirectory,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		listen: func(context.Context, string, string) (net.Listener, error) {
			record("listen")
			return newBlockingListener(), nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	select {
	case <-workerStarted:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if _, err := os.Stat(generationDirectory); err != nil {
		t.Fatalf("generation directory was removed before Close(): %v", err)
	}
	secondContext, secondCancel := context.WithCancel(context.Background())
	secondDone := make(chan error, 1)
	go func() { secondDone <- runtime.Run(secondContext) }()
	select {
	case <-workerStarted:
	case <-time.After(time.Second):
		t.Fatal("worker did not restart")
	}
	secondCancel()
	if err := <-secondDone; err != nil {
		t.Fatalf("second Run() error = %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := os.Stat(generationDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("generation directory still exists after Close(): %v", err)
	}
	orderMu.Lock()
	got := append([]string(nil), order...)
	orderMu.Unlock()
	wantPrefix := []string{"cleanup", "apply_host", "listen"}
	if len(got) < len(wantPrefix)+2 {
		t.Fatalf("order = %v", got)
	}
	for index, expected := range wantPrefix {
		if got[index] != expected {
			t.Fatalf("order = %v, want prefix %v", got, wantPrefix)
		}
	}
	if got[len(got)-1] != "remove_host" {
		t.Fatalf("order = %v, host firewall was not removed last", got)
	}
}

func TestRuntimeDoesNotListenWhenHostFirewallFails(t *testing.T) {
	hostFirewall := &recordingHostFirewall{applyErr: errors.New("nft failed")}
	runDirectory := privateTempDir(t)
	generationDirectory, err := os.MkdirTemp(runDirectory, "generation-")
	if err != nil {
		t.Fatal(err)
	}
	controlServer, err := control.NewServer(
		filepath.Join(runDirectory, "control.sock"),
		func() []worker.Snapshot { return nil },
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{
		dispatcher: testDispatcher(t), control: controlServer, firewall: hostFirewall,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		listen: func(context.Context, string, string) (net.Listener, error) {
			t.Fatal("listener opened after firewall failure")
			return nil, nil
		},
		runDirectory:        filepath.Dir(generationDirectory),
		generationDirectory: generationDirectory,
	}
	if err := runtime.Run(context.Background()); err == nil {
		t.Fatal("Run() unexpectedly succeeded")
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestRuntimeRollsBackWhenMetricsListenerFails(t *testing.T) {
	var orderMu sync.Mutex
	var order []string
	record := func(value string) {
		orderMu.Lock()
		defer orderMu.Unlock()
		order = append(order, value)
	}
	hostFirewall := &recordingHostFirewall{record: record}
	runDirectory := privateTempDir(t)
	generationDirectory, err := os.MkdirTemp(runDirectory, "generation-")
	if err != nil {
		t.Fatal(err)
	}
	controlServer, err := control.NewServer(
		filepath.Join(runDirectory, "control.sock"),
		func() []worker.Snapshot { return nil },
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	listenCalls := 0
	runtime := &Runtime{
		dispatcher: testDispatcher(t), control: controlServer,
		metrics: fakeMetricsService{}, metricsAddress: "127.0.0.1:9090",
		firewall: hostFirewall, logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		listenAddress: "127.0.0.1:1080",
		listen: func(context.Context, string, string) (net.Listener, error) {
			listenCalls++
			if listenCalls == 1 {
				return newBlockingListener(), nil
			}
			return nil, errors.New("metrics address occupied")
		},
		runDirectory: runDirectory, generationDirectory: generationDirectory,
	}
	if err := runtime.Run(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "Prometheus metrics") {
		t.Fatalf("Run() error = %v", err)
	}
	orderMu.Lock()
	got := append([]string(nil), order...)
	orderMu.Unlock()
	if len(got) < 2 || got[0] != "apply_host" || got[len(got)-1] != "remove_host" {
		t.Fatalf("rollback order = %v", got)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeRefreshesDirectHostPublicIPPolicy(t *testing.T) {
	registry := health.NewRegistry()
	if err := registry.SetHostWANIPs([]netip.Addr{netip.MustParseAddr("8.8.8.8")}); err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{
		hostIPChecker:  staticIPChecker{address: netip.MustParseAddr("1.1.1.1")},
		hostIPRegistry: registry,
		staticHostIPs:  []netip.Addr{netip.MustParseAddr("8.8.8.8")},
		hostIPInterval: time.Millisecond,
		hostIPTimeout:  time.Second,
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runtime.refreshHostPublicIP(ctx)
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		_, err := registry.VerifyAndRecord(
			"worker-1", netip.MustParseAddr("1.1.1.1"), health.VerificationPolicy{},
		)
		if err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("host public-IP policy was not refreshed")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
}

func TestRuntimeRestartsFailedWorkerController(t *testing.T) {
	var starts atomic.Int32
	secondStart := make(chan struct{})
	runtime := &Runtime{
		workerRestartBackoff: worker.Backoff{
			Minimum: time.Millisecond, Maximum: 2 * time.Millisecond,
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	controlled := controlledWorker{
		id: "worker-1",
		run: func(ctx context.Context) error {
			if starts.Add(1) == 1 {
				return errors.New("injected failure")
			}
			close(secondStart)
			<-ctx.Done()
			return nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runtime.superviseWorker(ctx, controlled)
		close(done)
	}()
	select {
	case <-secondStart:
	case <-time.After(time.Second):
		t.Fatal("worker controller was not restarted")
	}
	cancel()
	<-done
}

func TestRuntimeResetsWorkerBackoffAfterStableGeneration(t *testing.T) {
	starts := make(chan time.Time, 4)
	var generation atomic.Int32
	stableReturned := make(chan time.Time, 1)
	runtime := &Runtime{
		workerRestartBackoff: worker.Backoff{
			Minimum: 10 * time.Millisecond, Maximum: 100 * time.Millisecond,
		},
		workerRestartResetAfter: 20 * time.Millisecond,
		logger:                  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	controlled := controlledWorker{
		id: "worker-1",
		run: func(context.Context) error {
			current := generation.Add(1)
			starts <- time.Now()
			if current == 3 {
				time.Sleep(25 * time.Millisecond)
				stableReturned <- time.Now()
			}
			return errors.New("injected failure")
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runtime.superviseWorker(ctx, controlled)
		close(done)
	}()
	for range 3 {
		<-starts
	}
	returned := <-stableReturned
	fourth := <-starts
	if delay := fourth.Sub(returned); delay >= 25*time.Millisecond {
		cancel()
		<-done
		t.Fatalf("post-stability restart delay = %v, want reset near minimum", delay)
	}
	cancel()
	<-done
}

func TestRuntimeEnableDisableStopsAndRestartsWorker(t *testing.T) {
	model, err := worker.NewModel("worker-1")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 2)
	controlled := controlledWorker{
		id: "worker-1", model: model, lifecycle: newControlledLifecycle(false),
		run: func(ctx context.Context) error {
			if err := model.Transition(
				worker.StateCreatingNamespace, "test generation started", nil,
			); err != nil {
				return err
			}
			started <- struct{}{}
			<-ctx.Done()
			if err := model.Transition(worker.StateStopping, "test stop", nil); err != nil {
				return err
			}
			return model.Transition(worker.StateStopped, "test stopped", nil)
		},
	}
	runtime := &Runtime{
		workers: []controlledWorker{controlled},
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runtime.superviseWorker(ctx, runtime.workers[0])
		close(done)
	}()
	select {
	case <-started:
		t.Fatal("disabled worker started")
	case <-time.After(20 * time.Millisecond):
	}
	if err := runtime.SetWorkerEnabled(context.Background(), "worker-1", true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("enabled worker did not start")
	}
	if err := runtime.SetWorkerEnabled(context.Background(), "worker-1", false); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for model.Snapshot().State != worker.StateDisabled {
		if time.Now().After(deadline) {
			t.Fatalf("disabled state = %s", model.Snapshot().State)
		}
		time.Sleep(time.Millisecond)
	}
	if err := runtime.RestartWorker(context.Background(), "worker-1"); err == nil ||
		!strings.Contains(err.Error(), "disabled") {
		t.Fatalf("RestartWorker() error = %v", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker supervisor did not stop")
	}
}

func testDispatcher(t *testing.T) *dispatcher.Dispatcher {
	t.Helper()
	front, err := dispatcher.New(
		dispatcher.Config{
			Mode: balance.LeastConnections, SessionSeparator: "/",
			HandshakeTimeout: time.Second, ConnectTimeout: time.Second,
			IdleTimeout: time.Second,
		},
		dispatcher.NewRegistry(),
		failingConnector{},
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return front
}

type failingConnector struct{}

func (failingConnector) Connect(context.Context, balance.Candidate, string) (net.Conn, error) {
	return nil, errors.New("not used")
}

type fakeMetricsService struct{}

func (fakeMetricsService) Serve(context.Context, net.Listener) error {
	return errors.New("unexpected metrics serve")
}

type recordingCleaner struct {
	record func(string)
}

func (c *recordingCleaner) Delete(context.Context, netutil.Allocation) error {
	c.record("cleanup")
	return nil
}

type recordingHostFirewall struct {
	record   func(string)
	applyErr error
}

func (f *recordingHostFirewall) ApplyHost(context.Context, firewall.HostRules) error {
	if f.record != nil {
		f.record("apply_host")
	}
	return f.applyErr
}

func (f *recordingHostFirewall) RemoveHost(context.Context) error {
	if f.record != nil {
		f.record("remove_host")
	}
	return nil
}

type blockingListener struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingListener() *blockingListener {
	return &blockingListener{closed: make(chan struct{})}
}

func (l *blockingListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *blockingListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (*blockingListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

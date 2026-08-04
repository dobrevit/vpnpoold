package controller

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dobrevit/vpnpoold/internal/balance"
	"github.com/dobrevit/vpnpoold/internal/firewall"
	"github.com/dobrevit/vpnpoold/internal/netutil"
	"github.com/dobrevit/vpnpoold/internal/process"
	"github.com/dobrevit/vpnpoold/internal/worker"
)

func TestWorkerStartupIsFailClosedAndPublishesAfterVerification(t *testing.T) {
	fixture := newWorkerFixture(t, time.Hour)
	fixture.verifier.push(successfulVerification(), nil)
	done := fixture.run()
	fixture.vpn.ready(t)
	fixture.vpn.emit(VPNEvent{Type: VPNTunnelReady})
	fixture.publisher.waitForHealthy(t, 1)

	fixture.actions.requireOrder(t,
		"namespace:create",
		"firewall:bootstrap",
		"vpn:start",
		"firewall:active",
		"proxy:start",
		"verify",
		"publisher:healthy",
	)
	if snapshot := fixture.model.Snapshot(); !snapshot.Available ||
		snapshot.State != worker.StateHealthy {
		t.Fatalf("healthy snapshot = %+v", snapshot)
	}
	if got := fixture.model.Snapshot().HealthCheckSuccesses; got != 1 {
		t.Fatalf("health-check successes = %d", got)
	}

	fixture.cancel()
	if err := waitResult(t, done); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	fixture.actions.requireOrder(t,
		"publisher:unhealthy",
		"sessions:close",
		"firewall:strict",
		"proxy:signal",
		"vpn:stop",
		"namespace:delete",
	)
	if state := fixture.model.Snapshot().State; state != worker.StateStopped {
		t.Fatalf("final state = %s", state)
	}
}

func TestWorkerRequiresConsecutiveSuccessesBeforePublication(t *testing.T) {
	fixture := newWorkerFixtureWithThreshold(t, 5*time.Millisecond, 2)
	fixture.verifier.push(successfulVerification(), nil)
	done := fixture.run()
	fixture.vpn.ready(t)
	fixture.vpn.emit(VPNEvent{Type: VPNTunnelReady})
	fixture.actions.waitForCount(t, "verify", 2)
	if fixture.actions.count("publisher:healthy") != 0 {
		t.Fatal("worker was published after only one completed verification")
	}
	fixture.verifier.push(successfulVerification(), nil)
	fixture.publisher.waitForHealthy(t, 1)

	fixture.cancel()
	if err := waitResult(t, done); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestWorkerTunnelFailureWithdrawsAndRecovers(t *testing.T) {
	fixture := newWorkerFixture(t, time.Hour)
	fixture.verifier.push(successfulVerification(), nil)
	fixture.verifier.push(successfulVerification(), nil)
	done := fixture.run()
	fixture.vpn.ready(t)
	fixture.vpn.emit(VPNEvent{Type: VPNTunnelReady})
	fixture.publisher.waitForHealthy(t, 1)

	fixture.vpn.emit(VPNEvent{Type: VPNFailed, Err: errors.New("tun0 disappeared")})
	fixture.publisher.waitForUnhealthy(t, 1)
	fixture.actions.waitForCount(t, "firewall:strict", 1)
	fixture.actions.waitForCount(t, "proxy:signal", 1)
	if got := fixture.model.Snapshot().OpenVPNRestarts; got != 1 {
		t.Fatalf("OpenVPN restarts = %d", got)
	}
	if fixture.sessions.closedCount() != 1 {
		t.Fatalf("closed session batches = %d", fixture.sessions.closedCount())
	}

	fixture.vpn.emit(VPNEvent{Type: VPNTunnelReady})
	fixture.publisher.waitForHealthy(t, 1)
	if fixture.actions.count("proxy:start") != 2 {
		t.Fatalf("proxy starts = %d", fixture.actions.count("proxy:start"))
	}
	if fixture.model.Snapshot().State != worker.StateHealthy {
		t.Fatalf("recovered state = %s", fixture.model.Snapshot().State)
	}

	fixture.cancel()
	if err := waitResult(t, done); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestWorkerProxyFailureUsesProxyOnlyRecovery(t *testing.T) {
	fixture := newWorkerFixture(t, time.Hour)
	fixture.verifier.push(successfulVerification(), nil)
	fixture.verifier.push(successfulVerification(), nil)
	done := fixture.run()
	fixture.vpn.ready(t)
	fixture.vpn.emit(VPNEvent{Type: VPNTunnelReady})
	fixture.publisher.waitForHealthy(t, 1)

	fixture.proxy.latest(t).exit(errors.New("proxy crashed"))
	fixture.publisher.waitForUnhealthy(t, 1)
	fixture.publisher.waitForHealthy(t, 1)
	if got := fixture.model.Snapshot().ProxyRestarts; got != 1 {
		t.Fatalf("proxy restarts = %d", got)
	}
	if fixture.vpn.restartCount() != 0 {
		t.Fatalf("VPN restarts = %d, want 0", fixture.vpn.restartCount())
	}
	fixture.actions.requireOrder(t,
		"publisher:unhealthy",
		"sessions:close",
		"firewall:strict",
		"firewall:active",
		"proxy:start",
		"verify",
	)

	fixture.cancel()
	if err := waitResult(t, done); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestWorkerDrainAndUndrainAffectNewAssignmentsOnly(t *testing.T) {
	fixture := newWorkerFixture(t, time.Hour)
	fixture.verifier.push(successfulVerification(), nil)
	done := fixture.run()
	fixture.vpn.ready(t)
	fixture.vpn.emit(VPNEvent{Type: VPNTunnelReady})
	fixture.publisher.waitForHealthy(t, 1)

	commandContext, cancelCommand := context.WithTimeout(context.Background(), time.Second)
	if err := fixture.worker.SetDraining(commandContext, true); err != nil {
		t.Fatalf("SetDraining(true) error = %v", err)
	}
	if snapshot := fixture.model.Snapshot(); !snapshot.Draining || snapshot.Available {
		t.Fatalf("drained snapshot = %+v", snapshot)
	}
	if fixture.sessions.closedCount() != 0 {
		t.Fatal("draining terminated established sessions")
	}
	if err := fixture.worker.SetDraining(commandContext, false); err != nil {
		t.Fatalf("SetDraining(false) error = %v", err)
	}
	cancelCommand()
	if snapshot := fixture.model.Snapshot(); snapshot.Draining || !snapshot.Available {
		t.Fatalf("undrained snapshot = %+v", snapshot)
	}

	fixture.cancel()
	if err := waitResult(t, done); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestWorkerOperatorRestartFailsClosed(t *testing.T) {
	fixture := newWorkerFixture(t, time.Hour)
	fixture.verifier.push(successfulVerification(), nil)
	fixture.verifier.push(successfulVerification(), nil)
	done := fixture.run()
	fixture.vpn.ready(t)
	fixture.vpn.emit(VPNEvent{Type: VPNTunnelReady})
	fixture.publisher.waitForHealthy(t, 1)

	commandContext, cancelCommand := context.WithTimeout(context.Background(), time.Second)
	if err := fixture.worker.Restart(commandContext); err != nil {
		t.Fatalf("Restart() error = %v", err)
	}
	cancelCommand()
	fixture.publisher.waitForUnhealthy(t, 1)
	fixture.actions.waitForCount(t, "firewall:strict", 1)
	fixture.actions.waitForCount(t, "vpn:restart", 1)
	if got := fixture.model.Snapshot().OpenVPNRestarts; got != 1 {
		t.Fatalf("OpenVPN restarts = %d", got)
	}
	if fixture.sessions.closedCount() != 1 {
		t.Fatal("operator restart did not terminate worker sessions")
	}

	fixture.vpn.emit(VPNEvent{Type: VPNTunnelReady})
	fixture.publisher.waitForHealthy(t, 1)
	fixture.cancel()
	if err := waitResult(t, done); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestWorkerEgressFailureRestartsVPN(t *testing.T) {
	fixture := newWorkerFixture(t, 5*time.Millisecond)
	fixture.verifier.push(successfulVerification(), nil)
	fixture.verifier.push(Verification{}, errors.New("host WAN IP observed"))
	fixture.verifier.push(successfulVerification(), nil)
	done := fixture.run()
	fixture.vpn.ready(t)
	fixture.vpn.emit(VPNEvent{Type: VPNTunnelReady})
	fixture.publisher.waitForHealthy(t, 1)
	fixture.publisher.waitForUnhealthy(t, 1)
	fixture.actions.waitForCount(t, "vpn:restart", 1)
	snapshot := fixture.model.Snapshot()
	if snapshot.HealthCheckFailures != 1 || snapshot.OpenVPNRestarts != 1 {
		t.Fatalf("failure counters = %+v", snapshot)
	}
	if fixture.sessions.closedCount() == 0 {
		t.Fatal("egress failure did not close worker sessions")
	}

	fixture.vpn.emit(VPNEvent{Type: VPNTunnelReady})
	fixture.publisher.waitForHealthy(t, 1)
	if fixture.vpn.restartCount() != 1 {
		t.Fatalf("VPN restarts = %d", fixture.vpn.restartCount())
	}

	fixture.cancel()
	if err := waitResult(t, done); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestBootstrapFirewallFailureNeverStartsWorkload(t *testing.T) {
	fixture := newWorkerFixture(t, time.Hour)
	fixture.firewall.failMode = firewall.ModeBootstrap
	done := fixture.run()
	err := waitResult(t, done)
	if err == nil || !strings.Contains(err.Error(), "bootstrap firewall") {
		t.Fatalf("Run() error = %v", err)
	}
	if fixture.actions.count("vpn:start") != 0 || fixture.actions.count("proxy:start") != 0 {
		t.Fatalf("workload started after firewall failure: %v", fixture.actions.snapshot())
	}
	fixture.actions.requireOrder(t, "namespace:create", "firewall:bootstrap", "namespace:delete")
}

type workerFixture struct {
	worker    *Worker
	model     *worker.Model
	actions   *actionLog
	namespace *fakeNamespace
	firewall  *fakeFirewall
	vpn       *fakeVPN
	proxy     *fakeProxyLauncher
	verifier  *fakeVerifier
	publisher *fakePublisher
	sessions  *fakeSessions
	ctx       context.Context
	cancel    context.CancelFunc
}

func newWorkerFixture(t *testing.T, healthInterval time.Duration) *workerFixture {
	return newWorkerFixtureWithThreshold(t, healthInterval, 1)
}

func newWorkerFixtureWithThreshold(
	t *testing.T,
	healthInterval time.Duration,
	successThreshold int,
) *workerFixture {
	t.Helper()
	actions := &actionLog{}
	model, err := worker.NewModel("worker-1")
	if err != nil {
		t.Fatal(err)
	}
	namespace := &fakeNamespace{actions: actions}
	firewallManager := &fakeFirewall{actions: actions, failMode: firewall.Mode(255)}
	vpn := newFakeVPN(actions)
	proxy := &fakeProxyLauncher{actions: actions}
	verifier := &fakeVerifier{actions: actions, outcomes: make(chan verifyOutcome, 8)}
	publisher := &fakePublisher{actions: actions, healthy: make(chan bool, 16)}
	sessions := &fakeSessions{actions: actions}
	spec := WorkerSpec{
		ID: "worker-1",
		Allocation: netutil.Allocation{
			WorkerID:         "worker-1",
			Namespace:        "vpnpool-1234567890",
			HostVeth:         "vph1234567890",
			NamespaceVeth:    "vpn1234567890",
			Subnet:           netip.MustParsePrefix("10.231.0.0/30"),
			HostAddress:      netip.MustParsePrefix("10.231.0.1/30"),
			NamespaceAddress: netip.MustParsePrefix("10.231.0.2/30"),
		},
		FirewallRules: firewall.WorkerRules{
			VethInterface:   "vpn1234567890",
			TunnelInterface: "tun0",
			HostAddress:     netip.MustParseAddr("10.231.0.1"),
			ProxyPort:       1081,
			OpenVPNEndpoints: []firewall.Endpoint{{
				Address: netip.MustParseAddr("198.51.100.10"), Protocol: "udp", Port: 1194,
			}},
		},
		Candidate: balance.Candidate{
			ID: "worker-1", Address: "10.231.0.2:1081", Weight: 1,
		},
		HealthInterval:   healthInterval,
		HealthTimeout:    minDuration(healthInterval, 50*time.Millisecond),
		SuccessThreshold: successThreshold,
		StopTimeout:      50 * time.Millisecond,
		ProxyBackoff: worker.Backoff{
			Minimum: time.Millisecond,
			Maximum: 2 * time.Millisecond,
		},
	}
	controller, err := NewWorker(spec, Dependencies{
		Namespace:  namespace,
		Firewall:   firewallManager,
		VPN:        vpn,
		StartProxy: proxy.Start,
		Verifier:   verifier,
		Publisher:  publisher,
		Sessions:   sessions,
		Model:      model,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &workerFixture{
		worker: controller, model: model, actions: actions,
		namespace: namespace, firewall: firewallManager, vpn: vpn, proxy: proxy,
		verifier: verifier, publisher: publisher, sessions: sessions,
		ctx: ctx, cancel: cancel,
	}
}

func (f *workerFixture) run() <-chan error {
	done := make(chan error, 1)
	go func() { done <- f.worker.Run(f.ctx) }()
	return done
}

func successfulVerification() Verification {
	return Verification{
		PublicIP:          netip.MustParseAddr("8.8.8.8"),
		ExpectedIPMatches: true,
		PublicIPUnique:    true,
	}
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func waitResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("worker controller did not stop")
		return nil
	}
}

type actionLog struct {
	mu      sync.Mutex
	actions []string
}

func (l *actionLog) add(action string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.actions = append(l.actions, action)
}

func (l *actionLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.actions...)
}

func (l *actionLog) count(action string) int {
	count := 0
	for _, current := range l.snapshot() {
		if current == action {
			count++
		}
	}
	return count
}

func (l *actionLog) waitForCount(t *testing.T, action string, count int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if l.count(action) >= count {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("action %q count = %d, want at least %d; actions=%v", action, l.count(action), count, l.snapshot())
}

func (l *actionLog) requireOrder(t *testing.T, expected ...string) {
	t.Helper()
	actions := l.snapshot()
	position := 0
	for _, action := range actions {
		if position < len(expected) && action == expected[position] {
			position++
		}
	}
	if position != len(expected) {
		t.Fatalf("actions %v do not contain ordered sequence %v", actions, expected)
	}
}

type fakeNamespace struct {
	actions *actionLog
}

func (n *fakeNamespace) Create(context.Context, netutil.Allocation) error {
	n.actions.add("namespace:create")
	return nil
}

func (n *fakeNamespace) Delete(context.Context, netutil.Allocation) error {
	n.actions.add("namespace:delete")
	return nil
}

type fakeFirewall struct {
	actions  *actionLog
	failMode firewall.Mode
}

func (f *fakeFirewall) Apply(_ context.Context, _ string, rules firewall.WorkerRules) error {
	f.actions.add("firewall:" + rules.Mode.String())
	if rules.Mode == f.failMode {
		return errors.New("injected firewall failure")
	}
	return nil
}

type fakeVPN struct {
	actions  *actionLog
	events   chan<- VPNEvent
	started  chan struct{}
	mu       sync.Mutex
	restarts int
}

func newFakeVPN(actions *actionLog) *fakeVPN {
	return &fakeVPN{actions: actions, started: make(chan struct{})}
}

func (v *fakeVPN) Run(ctx context.Context, events chan<- VPNEvent) error {
	v.actions.add("vpn:start")
	v.mu.Lock()
	v.events = events
	v.mu.Unlock()
	close(v.started)
	<-ctx.Done()
	v.actions.add("vpn:stop")
	return nil
}

func (v *fakeVPN) Restart() {
	v.actions.add("vpn:restart")
	v.mu.Lock()
	v.restarts++
	v.mu.Unlock()
}

func (v *fakeVPN) ready(t *testing.T) {
	t.Helper()
	select {
	case <-v.started:
	case <-time.After(time.Second):
		t.Fatal("VPN service did not start")
	}
}

func (v *fakeVPN) emit(event VPNEvent) {
	v.mu.Lock()
	events := v.events
	v.mu.Unlock()
	events <- event
}

func (v *fakeVPN) restartCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.restarts
}

type fakeProxyLauncher struct {
	actions   *actionLog
	mu        sync.Mutex
	processes []*fakeProcess
}

func (l *fakeProxyLauncher) Start(context.Context) (process.ManagedProcess, error) {
	l.actions.add("proxy:start")
	l.mu.Lock()
	defer l.mu.Unlock()
	running := newFakeProcess(100+len(l.processes), l.actions)
	l.processes = append(l.processes, running)
	return running, nil
}

func (l *fakeProxyLauncher) latest(t *testing.T) *fakeProcess {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.processes) == 0 {
		t.Fatal("no proxy process")
	}
	return l.processes[len(l.processes)-1]
}

type fakeProcess struct {
	pid     int
	actions *actionLog
	done    chan error
	once    sync.Once
}

func newFakeProcess(pid int, actions *actionLog) *fakeProcess {
	return &fakeProcess{pid: pid, actions: actions, done: make(chan error, 1)}
}

func (p *fakeProcess) PID() int    { return p.pid }
func (p *fakeProcess) Wait() error { return <-p.done }
func (p *fakeProcess) Signal(os.Signal) error {
	p.actions.add("proxy:signal")
	p.exit(nil)
	return nil
}
func (p *fakeProcess) Kill() error {
	p.actions.add("proxy:kill")
	p.exit(nil)
	return nil
}
func (p *fakeProcess) exit(err error) {
	p.once.Do(func() { p.done <- err })
}

type verifyOutcome struct {
	verification Verification
	err          error
}

type fakeVerifier struct {
	actions     *actionLog
	outcomes    chan verifyOutcome
	mu          sync.Mutex
	withdrawals int
}

func (v *fakeVerifier) Withdraw() {
	v.mu.Lock()
	v.withdrawals++
	v.mu.Unlock()
}

func (v *fakeVerifier) push(verification Verification, err error) {
	v.outcomes <- verifyOutcome{verification: verification, err: err}
}

func (v *fakeVerifier) Verify(ctx context.Context) (Verification, error) {
	v.actions.add("verify")
	select {
	case outcome := <-v.outcomes:
		return outcome.verification, outcome.err
	case <-ctx.Done():
		return Verification{}, ctx.Err()
	}
}

type fakePublisher struct {
	actions  *actionLog
	healthy  chan bool
	mu       sync.Mutex
	draining bool
}

func (p *fakePublisher) Upsert(candidate balance.Candidate) error {
	p.actions.add("publisher:healthy")
	p.healthy <- candidate.Healthy
	return nil
}

func (p *fakePublisher) SetHealthy(_ string, healthy bool) bool {
	p.actions.add("publisher:unhealthy")
	p.healthy <- healthy
	return true
}

func (p *fakePublisher) SetDraining(_ string, draining bool) bool {
	p.actions.add("publisher:draining")
	p.mu.Lock()
	p.draining = draining
	p.mu.Unlock()
	return true
}

func (p *fakePublisher) waitForHealthy(t *testing.T, occurrence int) {
	t.Helper()
	p.waitFor(t, true, occurrence)
}

func (p *fakePublisher) waitForUnhealthy(t *testing.T, occurrence int) {
	t.Helper()
	p.waitFor(t, false, occurrence)
}

func (p *fakePublisher) waitFor(t *testing.T, value bool, occurrence int) {
	t.Helper()
	count := 0
	deadline := time.After(time.Second)
	for {
		select {
		case current := <-p.healthy:
			if current == value {
				count++
				if count == occurrence {
					return
				}
			}
		case <-deadline:
			t.Fatalf("publisher did not emit %t occurrence %d", value, occurrence)
		}
	}
}

type fakeSessions struct {
	actions *actionLog
	mu      sync.Mutex
	closed  int
}

func (s *fakeSessions) CloseWorkerSessions(string) int {
	s.actions.add("sessions:close")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed++
	return 1
}

func (s *fakeSessions) closedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

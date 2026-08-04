package openvpn

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dobrevit/vpnpoold/internal/process"
	"github.com/dobrevit/vpnpoold/internal/worker"
)

func TestSupervisorStopsHealthyProcessGracefully(t *testing.T) {
	running := newFakeManagedProcess(101)
	probe := &sequenceProbe{results: []error{nil}}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	supervisor := testSupervisor(
		func(context.Context) (process.ManagedProcess, error) { return running, nil },
		probe,
		func(event Event) {
			if event.Type == EventTunnelReady {
				close(ready)
			}
		},
	)
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("supervisor did not report tunnel ready")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if running.signals != 1 || running.kills != 0 {
		t.Fatalf("signals=%d kills=%d", running.signals, running.kills)
	}
}

func TestSupervisorRestartsAfterTunnelFailure(t *testing.T) {
	var mu sync.Mutex
	var processes []*fakeManagedProcess
	start := func(context.Context) (process.ManagedProcess, error) {
		mu.Lock()
		defer mu.Unlock()
		running := newFakeManagedProcess(100 + len(processes))
		processes = append(processes, running)
		return running, nil
	}
	probe := &sequenceProbe{results: []error{
		nil,
		errors.New("tun0 missing"),
		nil,
	}}
	ctx, cancel := context.WithCancel(context.Background())
	readyCount := 0
	readyTwice := make(chan struct{})
	supervisor := testSupervisor(start, probe, func(event Event) {
		if event.Type == EventTunnelReady {
			readyCount++
			if readyCount == 2 {
				close(readyTwice)
			}
		}
	})
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	select {
	case <-readyTwice:
	case <-time.After(time.Second):
		t.Fatal("supervisor did not restart and recover")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(processes) != 2 {
		t.Fatalf("process starts = %d", len(processes))
	}
	if processes[0].signals != 1 {
		t.Fatalf("failed tunnel process signals = %d", processes[0].signals)
	}
}

func TestSupervisorDetectsCrashLoop(t *testing.T) {
	start := func(context.Context) (process.ManagedProcess, error) {
		running := newFakeManagedProcess(100)
		running.exit(nil)
		return running, nil
	}
	supervisor := testSupervisor(start, &sequenceProbe{results: []error{errors.New("not ready")}}, nil)
	supervisor.Config.CrashLoopLimit = 3
	err := supervisor.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "rapid crash loop") {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestSupervisorWaitsForManagementConnectedBeforeTunnelProbe(t *testing.T) {
	running := newFakeManagedProcess(101)
	probe := &sequenceProbe{results: []error{nil}}
	management := &controlledManagementWatcher{
		events: make(chan ManagementState, 1),
	}
	supervisor := testSupervisor(
		func(context.Context) (process.ManagedProcess, error) { return running, nil },
		probe,
		nil,
	)
	supervisor.Management = management
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	time.Sleep(10 * time.Millisecond)
	if calls := probe.callCount(); calls != 0 {
		t.Fatalf("tunnel probe calls before management CONNECTED = %d", calls)
	}
	management.events <- ManagementState{Name: managementStateConnected, Successful: true}
	deadline := time.After(time.Second)
	for probe.callCount() == 0 {
		select {
		case <-deadline:
			t.Fatal("tunnel probe did not run after management CONNECTED")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func testSupervisor(start StartFunc, probe TunnelProbe, event func(Event)) *Supervisor {
	return &Supervisor{
		Config: SupervisorConfig{
			StartupTimeout:  50 * time.Millisecond,
			CheckInterval:   time.Millisecond,
			CheckTimeout:    10 * time.Millisecond,
			StopTimeout:     20 * time.Millisecond,
			CrashLoopWindow: time.Second,
			CrashLoopLimit:  10,
			Backoff: worker.Backoff{
				Minimum: time.Millisecond,
				Maximum: 2 * time.Millisecond,
			},
		},
		Start:      start,
		Probe:      probe,
		Management: connectedManagementWatcher{},
		OnEvent:    event,
	}
}

type sequenceProbe struct {
	mu      sync.Mutex
	results []error
	index   int
}

func (p *sequenceProbe) Check(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.results) == 0 {
		return nil
	}
	index := p.index
	if index >= len(p.results) {
		index = len(p.results) - 1
	} else {
		p.index++
	}
	return p.results[index]
}

func (p *sequenceProbe) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.index
}

type connectedManagementWatcher struct{}

func (connectedManagementWatcher) Watch(ctx context.Context, events chan<- ManagementState) error {
	select {
	case events <- ManagementState{Name: managementStateConnected, Successful: true}:
	case <-ctx.Done():
		return nil
	}
	<-ctx.Done()
	return nil
}

type controlledManagementWatcher struct {
	events chan ManagementState
}

func (w *controlledManagementWatcher) Watch(ctx context.Context, events chan<- ManagementState) error {
	for {
		select {
		case event := <-w.events:
			select {
			case events <- event:
			case <-ctx.Done():
				return nil
			}
		case <-ctx.Done():
			return nil
		}
	}
}

type fakeManagedProcess struct {
	pid     int
	done    chan error
	once    sync.Once
	signals int
	kills   int
}

func newFakeManagedProcess(pid int) *fakeManagedProcess {
	return &fakeManagedProcess{pid: pid, done: make(chan error, 1)}
}

func (p *fakeManagedProcess) PID() int {
	return p.pid
}

func (p *fakeManagedProcess) Wait() error {
	return <-p.done
}

func (p *fakeManagedProcess) Signal(os.Signal) error {
	p.signals++
	p.exit(nil)
	return nil
}

func (p *fakeManagedProcess) Kill() error {
	p.kills++
	p.exit(nil)
	return nil
}

func (p *fakeManagedProcess) exit(err error) {
	p.once.Do(func() {
		p.done <- err
		close(p.done)
	})
}

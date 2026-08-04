package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dobrevit/vpnpoold/internal/balance"
	"github.com/dobrevit/vpnpoold/internal/control"
	"github.com/dobrevit/vpnpoold/internal/firewall"
	"github.com/dobrevit/vpnpoold/internal/health"
	"github.com/dobrevit/vpnpoold/internal/netutil"
	"github.com/dobrevit/vpnpoold/internal/proxy/dispatcher"
	"github.com/dobrevit/vpnpoold/internal/worker"
)

type hostFirewall interface {
	ApplyHost(context.Context, firewall.HostRules) error
	RemoveHost(context.Context) error
}

type controlledWorker struct {
	id          string
	run         func(context.Context) error
	setDraining func(context.Context, bool) error
	restart     func(context.Context) error
	model       *worker.Model
	allocation  netutil.Allocation
	lifecycle   *controlledLifecycle
}

type controlledLifecycle struct {
	mu         sync.Mutex
	enabled    bool
	overridden bool
	cancel     context.CancelFunc
	changed    chan struct{}
}

func newControlledLifecycle(enabled bool) *controlledLifecycle {
	return &controlledLifecycle{enabled: enabled, changed: make(chan struct{}, 1)}
}

func (l *controlledLifecycle) isEnabled() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enabled
}

func (l *controlledLifecycle) state() (enabled, overridden bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enabled, l.overridden
}

func (l *controlledLifecycle) setEnabled(enabled, overridden bool) {
	l.mu.Lock()
	if overridden {
		l.overridden = true
	}
	if l.enabled == enabled {
		l.mu.Unlock()
		return
	}
	l.enabled = enabled
	cancel := l.cancel
	l.mu.Unlock()
	if !enabled && cancel != nil {
		cancel()
	}
	select {
	case l.changed <- struct{}{}:
	default:
	}
}

func (l *controlledLifecycle) setCancel(cancel context.CancelFunc) {
	l.mu.Lock()
	l.cancel = cancel
	enabled := l.enabled
	l.mu.Unlock()
	if !enabled {
		cancel()
	}
}

func (l *controlledLifecycle) clearCancel() {
	l.mu.Lock()
	l.cancel = nil
	l.mu.Unlock()
}

type staleCleaner interface {
	Delete(context.Context, netutil.Allocation) error
}

type PublicIPChecker interface {
	Check(context.Context) (netip.Addr, error)
}

type metricsService interface {
	Serve(context.Context, net.Listener) error
}

type Runtime struct {
	workers                 []controlledWorker
	namespace               staleCleaner
	cleanupStale            bool
	dispatcher              *dispatcher.Dispatcher
	pool                    *dispatcher.Registry
	control                 *control.Server
	metrics                 metricsService
	firewall                hostFirewall
	hostRules               firewall.HostRules
	listenAddress           string
	metricsAddress          string
	runDirectory            string
	generationDirectory     string
	hostIPChecker           PublicIPChecker
	hostIPRegistry          *health.Registry
	staticHostIPs           []netip.Addr
	hostIPInterval          time.Duration
	hostIPTimeout           time.Duration
	workerRestartBackoff    worker.Backoff
	workerRestartResetAfter time.Duration
	logger                  *slog.Logger
	listen                  func(context.Context, string, string) (net.Listener, error)
	reload                  func(context.Context) error
	closed                  atomic.Bool
	runMu                   sync.Mutex
	running                 bool
}

type Running struct {
	done chan error
	once sync.Once
	err  error
}

func (r *Runtime) Start(ctx context.Context) (*Running, error) {
	if ctx == nil {
		return nil, errors.New("runtime context is required")
	}
	if r == nil || r.dispatcher == nil || r.control == nil ||
		r.firewall == nil || r.listen == nil {
		return nil, errors.New("daemon runtime is not fully configured")
	}
	if r.metricsAddress != "" && r.metrics == nil {
		return nil, errors.New("metrics listener is configured without a metrics server")
	}
	r.runMu.Lock()
	if r.closed.Load() {
		r.runMu.Unlock()
		return nil, errors.New("daemon runtime is closed")
	}
	if r.running {
		r.runMu.Unlock()
		return nil, errors.New("daemon runtime is already running")
	}
	r.running = true
	r.runMu.Unlock()
	release := func() {
		r.runMu.Lock()
		r.running = false
		r.runMu.Unlock()
	}

	if r.cleanupStale {
		if r.namespace == nil {
			release()
			return nil, errors.New("stale cleanup is enabled but no namespace manager is configured")
		}
		for _, controlled := range r.workers {
			if err := r.namespace.Delete(ctx, controlled.allocation); err != nil {
				release()
				return nil, fmt.Errorf("clean stale resources for worker %q: %w", controlled.id, err)
			}
		}
	}
	if err := r.firewall.ApplyHost(ctx, r.hostRules); err != nil {
		release()
		return nil, fmt.Errorf("install host bootstrap firewall: %w", err)
	}

	runContext, cancel := context.WithCancel(ctx)
	controlListener, err := r.control.Listen()
	if err != nil {
		cancel()
		cleanupErr := r.removeHostFirewall()
		release()
		return nil, errors.Join(
			fmt.Errorf("listen for daemon control clients: %w", err),
			cleanupErr,
		)
	}
	serviceDone := make(chan serviceResult, 3)
	go func() {
		serviceDone <- serviceResult{name: "control socket", err: r.control.Serve(runContext, controlListener)}
	}()

	listener, err := r.listen(ctx, "tcp", r.listenAddress)
	if err != nil {
		cancel()
		result := <-serviceDone
		cleanupErr := r.removeHostFirewall()
		release()
		return nil, errors.Join(
			fmt.Errorf("listen for host SOCKS5 clients: %w", err),
			result.err,
			cleanupErr,
		)
	}
	r.logger.Info("dispatcher listening", slog.String("listen", r.listenAddress))

	go func() {
		serviceDone <- serviceResult{name: "host dispatcher", err: r.dispatcher.Serve(runContext, listener)}
	}()
	serviceCount := 2
	if r.metrics != nil {
		metricsListener, listenErr := r.listen(ctx, "tcp", r.metricsAddress)
		if listenErr != nil {
			cancel()
			var serviceErr error
			for completed := 0; completed < serviceCount; completed++ {
				result := <-serviceDone
				serviceErr = errors.Join(serviceErr, result.err)
			}
			cleanupErr := r.removeHostFirewall()
			release()
			return nil, errors.Join(
				fmt.Errorf("listen for Prometheus metrics: %w", listenErr),
				serviceErr,
				cleanupErr,
			)
		}
		serviceCount++
		r.logger.Info("metrics listening", slog.String("listen", r.metricsAddress))
		go func() {
			serviceDone <- serviceResult{
				name: "metrics endpoint",
				err:  r.metrics.Serve(runContext, metricsListener),
			}
		}()
	}

	var workerGroup sync.WaitGroup
	if r.hostIPChecker != nil && r.hostIPRegistry != nil &&
		r.hostIPInterval > 0 && r.hostIPTimeout > 0 {
		workerGroup.Add(1)
		go func() {
			defer workerGroup.Done()
			r.refreshHostPublicIP(runContext)
		}()
	}
	for index := range r.workers {
		if r.workers[index].lifecycle == nil {
			r.workers[index].lifecycle = newControlledLifecycle(true)
		}
	}
	for _, controlled := range r.workers {
		controlled := controlled
		workerGroup.Add(1)
		go func() {
			defer workerGroup.Done()
			r.superviseWorker(runContext, controlled)
		}()
	}

	running := &Running{done: make(chan error, 1)}
	go func() {
		runErr := r.coordinate(ctx, cancel, serviceDone, serviceCount, &workerGroup)
		release()
		running.done <- runErr
	}()
	return running, nil
}

func (r *Runtime) superviseWorker(ctx context.Context, controlled controlledWorker) {
	if controlled.lifecycle == nil {
		controlled.lifecycle = newControlledLifecycle(true)
	}
	backoff := r.workerRestartBackoff
	if err := backoff.Validate(); err != nil {
		backoff = worker.Backoff{Minimum: time.Second, Maximum: 30 * time.Second}
	}
	var failures uint
	for {
		if !controlled.lifecycle.isEnabled() {
			r.markWorkerDisabled(controlled)
			select {
			case <-ctx.Done():
				return
			case <-controlled.lifecycle.changed:
				continue
			}
		}
		generationContext, cancelGeneration := context.WithCancel(ctx)
		controlled.lifecycle.setCancel(cancelGeneration)
		generationStarted := time.Now()
		err := controlled.run(generationContext)
		controlled.lifecycle.clearCancel()
		cancelGeneration()
		if ctx.Err() != nil {
			return
		}
		if !controlled.lifecycle.isEnabled() {
			failures = 0
			r.markWorkerDisabled(controlled)
			continue
		}
		if err == nil {
			err = errors.New("worker controller stopped unexpectedly")
		}
		if r.workerRestartResetAfter > 0 &&
			time.Since(generationStarted) >= r.workerRestartResetAfter {
			failures = 0
		}
		r.logger.Error("worker controller stopped; scheduling restart",
			slog.String("worker", controlled.id),
			slog.String("error", err.Error()),
		)
		delay, backoffErr := backoff.Duration(failures)
		if backoffErr != nil {
			return
		}
		failures++
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-controlled.lifecycle.changed:
			if !timer.Stop() {
				<-timer.C
			}
			continue
		case <-timer.C:
		}
	}
}

func (r *Runtime) markWorkerDisabled(controlled controlledWorker) {
	state := controlled.model.Snapshot().State
	if state == worker.StateDisabled {
		return
	}
	if state != worker.StateStopped && state != worker.StateFailed {
		r.logger.Error("worker did not stop before disable",
			slog.String("worker", controlled.id),
			slog.String("state", state.String()),
		)
		return
	}
	if err := controlled.model.Transition(worker.StateDisabled, "disabled by operator", nil); err != nil {
		r.logger.Error("mark worker disabled",
			slog.String("worker", controlled.id),
			slog.String("error", err.Error()),
		)
	}
}

func (r *Runtime) refreshHostPublicIP(ctx context.Context) {
	ticker := time.NewTicker(r.hostIPInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkContext, cancel := context.WithTimeout(ctx, r.hostIPTimeout)
			address, err := r.hostIPChecker.Check(checkContext)
			cancel()
			if err != nil {
				r.logger.Warn("direct host public-IP refresh failed",
					slog.String("error", err.Error()),
				)
				continue
			}
			if err := health.ValidatePublicIP(address); err != nil {
				r.logger.Warn("direct host public-IP refresh rejected")
				continue
			}
			addresses := append([]netip.Addr(nil), r.staticHostIPs...)
			addresses = append(addresses, address.Unmap())
			if err := r.hostIPRegistry.SetHostWANIPs(addresses); err != nil {
				r.logger.Warn("update direct host public-IP policy failed")
			}
		}
	}
}

func (r *Runtime) Run(ctx context.Context) error {
	running, err := r.Start(ctx)
	if err != nil {
		return err
	}
	return running.Wait()
}

func (r *Runtime) coordinate(
	ctx context.Context,
	cancel context.CancelFunc,
	serviceDone <-chan serviceResult,
	serviceCount int,
	workerGroup *sync.WaitGroup,
) (runErr error) {
	defer cancel()
	completedServices := 0
	select {
	case <-ctx.Done():
		cancel()
	case result := <-serviceDone:
		completedServices = 1
		cancel()
		if result.err != nil {
			runErr = fmt.Errorf("serve %s: %w", result.name, result.err)
		} else if ctx.Err() == nil {
			runErr = fmt.Errorf("%s stopped unexpectedly", result.name)
		}
	}
	for completedServices < serviceCount {
		result := <-serviceDone
		completedServices++
		if result.err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("serve %s: %w", result.name, result.err))
		}
	}
	workerGroup.Wait()
	runErr = errors.Join(runErr, r.removeHostFirewall())
	r.logger.Info("daemon runtime stopped")
	return runErr
}

func (r *Runtime) removeHostFirewall() error {
	cleanupContext, cancel := context.WithTimeout(context.Background(), workerStopTimeout)
	defer cancel()
	if err := r.firewall.RemoveHost(cleanupContext); err != nil {
		return fmt.Errorf("remove host bootstrap firewall: %w", err)
	}
	return nil
}

func (r *Running) Wait() error {
	if r == nil {
		return errors.New("running daemon handle is required")
	}
	r.once.Do(func() {
		r.err = <-r.done
	})
	return r.err
}

type serviceResult struct {
	name string
	err  error
}

func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	r.runMu.Lock()
	defer r.runMu.Unlock()
	if r.running {
		return errors.New("cannot close a running daemon runtime")
	}
	if !r.closed.CompareAndSwap(false, true) {
		return nil
	}
	return removeGenerationDirectory(r.runDirectory, r.generationDirectory)
}

func (r *Runtime) WorkerSnapshots() []worker.Snapshot {
	if r == nil {
		return nil
	}
	candidates := make(map[string]balance.Candidate)
	if r.pool != nil {
		for _, candidate := range r.pool.Snapshot() {
			candidates[candidate.ID] = candidate
		}
	}
	var dispatcherStats map[string]dispatcher.WorkerStats
	if r.dispatcher != nil {
		dispatcherStats = r.dispatcher.WorkerStats()
	}
	result := make([]worker.Snapshot, 0, len(r.workers))
	for _, controlled := range r.workers {
		snapshot := controlled.model.Snapshot()
		snapshot.Enabled = true
		if controlled.lifecycle != nil {
			snapshot.Enabled, snapshot.EnabledOverridden = controlled.lifecycle.state()
		}
		if candidate, exists := candidates[controlled.id]; exists {
			snapshot.ActiveConnections = candidate.ActiveConnections
		}
		if stats, exists := dispatcherStats[controlled.id]; exists {
			snapshot.ConnectionsTotal = stats.ConnectionsTotal
			snapshot.BackendSelections = stats.BackendSelections
			snapshot.BytesFromClients = stats.BytesFromClients
			snapshot.BytesToClients = stats.BytesToClients
		}
		result = append(result, snapshot)
	}
	return result
}

func (r *Runtime) SetWorkerDraining(ctx context.Context, workerID string, draining bool) error {
	for _, controlled := range r.workers {
		if controlled.id == workerID {
			if controlled.setDraining == nil {
				return fmt.Errorf("worker %q does not support draining", workerID)
			}
			return controlled.setDraining(ctx, draining)
		}
	}
	return fmt.Errorf("worker %q is not configured", workerID)
}

func (r *Runtime) Reload(ctx context.Context) error {
	if r.reload == nil {
		return errors.New("reload is unavailable")
	}
	return r.reload(ctx)
}

func (r *Runtime) SetReloadFunc(reload func(context.Context) error) {
	r.reload = reload
}

func (r *Runtime) SetWorkerEnabled(_ context.Context, workerID string, enabled bool) error {
	for index := range r.workers {
		controlled := &r.workers[index]
		if controlled.id != workerID {
			continue
		}
		if controlled.lifecycle == nil {
			controlled.lifecycle = newControlledLifecycle(true)
		}
		controlled.lifecycle.setEnabled(enabled, true)
		if !enabled {
			controlled.model.SetDraining(false)
			if r.hostIPRegistry != nil {
				r.hostIPRegistry.Remove(workerID)
			}
			if r.pool != nil {
				r.pool.SetDraining(workerID, false)
				r.pool.SetHealthy(workerID, false)
			}
		}
		return nil
	}
	return fmt.Errorf("worker %q is not configured", workerID)
}

func (r *Runtime) RestartWorker(ctx context.Context, workerID string) error {
	for _, controlled := range r.workers {
		if controlled.id == workerID {
			if controlled.lifecycle != nil && !controlled.lifecycle.isEnabled() {
				return fmt.Errorf("worker %q is disabled", workerID)
			}
			if controlled.restart == nil {
				return fmt.Errorf("worker %q does not support restart", workerID)
			}
			return controlled.restart(ctx)
		}
	}
	return fmt.Errorf("worker %q is not configured", workerID)
}

func (r *Runtime) SetInitialWorkerEnabled(workerID string, enabled bool) error {
	for index := range r.workers {
		controlled := &r.workers[index]
		if controlled.id == workerID {
			if controlled.lifecycle == nil {
				controlled.lifecycle = newControlledLifecycle(enabled)
			} else {
				controlled.lifecycle.setEnabled(enabled, true)
			}
			return nil
		}
	}
	return fmt.Errorf("worker %q is not configured", workerID)
}

// SetInitialWorkerDraining carries operator drain intent into a prepared reload
// generation before its controllers start.
func (r *Runtime) SetInitialWorkerDraining(workerID string, draining bool) error {
	for _, controlled := range r.workers {
		if controlled.id == workerID {
			controlled.model.SetDraining(draining)
			return nil
		}
	}
	return fmt.Errorf("worker %q is not configured", workerID)
}

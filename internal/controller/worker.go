package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/dobrevit/vpnpoold/internal/firewall"
	"github.com/dobrevit/vpnpoold/internal/process"
	workermodel "github.com/dobrevit/vpnpoold/internal/worker"
)

type Worker struct {
	spec     WorkerSpec
	deps     Dependencies
	commands chan workerCommand
	runMu    sync.Mutex
	running  bool
	runDone  chan struct{}
}

type workerCommandType uint8

const (
	commandSetDraining workerCommandType = iota
	commandRestart
)

type workerCommand struct {
	kind     workerCommandType
	draining bool
	result   chan error
}

type proxyRuntime struct {
	process process.ManagedProcess
	cancel  context.CancelFunc
	done    <-chan error
}

type verificationResult struct {
	epoch        uint64
	verification Verification
	err          error
}

type proxyStartResult struct {
	epoch   uint64
	runtime *proxyRuntime
	err     error
}

func NewWorker(spec WorkerSpec, dependencies Dependencies) (*Worker, error) {
	if spec.ID == "" || spec.ID != spec.Allocation.WorkerID ||
		spec.ID != spec.Candidate.ID {
		return nil, errors.New("worker IDs must be non-empty and consistent")
	}
	if spec.Candidate.Healthy {
		return nil, errors.New("worker candidate must start unhealthy")
	}
	activeRules := spec.FirewallRules
	activeRules.Mode = firewall.ModeActive
	if err := activeRules.Validate(); err != nil {
		return nil, fmt.Errorf("worker active firewall rules: %w", err)
	}
	if spec.FirewallRules.VethInterface != spec.Allocation.NamespaceVeth ||
		spec.FirewallRules.HostAddress != spec.Allocation.HostAddress.Addr() {
		return nil, errors.New("worker firewall does not match its namespace allocation")
	}
	candidateHost, candidatePortText, err := net.SplitHostPort(spec.Candidate.Address)
	if err != nil {
		return nil, errors.New("worker candidate address is invalid")
	}
	candidateAddress, err := netip.ParseAddr(candidateHost)
	if err != nil || candidateAddress != spec.Allocation.NamespaceAddress.Addr() {
		return nil, errors.New("worker candidate must use its namespace veth address")
	}
	candidatePort, err := strconv.Atoi(candidatePortText)
	if err != nil || candidatePort != int(spec.FirewallRules.ProxyPort) {
		return nil, errors.New("worker candidate and firewall proxy ports must match")
	}
	if spec.Candidate.Weight < 1 || spec.Candidate.Weight > 100 {
		return nil, errors.New("worker candidate weight must be between 1 and 100")
	}
	if spec.HealthInterval <= 0 || spec.HealthTimeout <= 0 ||
		spec.HealthTimeout > spec.HealthInterval || spec.SuccessThreshold <= 0 ||
		spec.StopTimeout <= 0 {
		return nil, errors.New("worker health and stop durations are invalid")
	}
	if err := spec.ProxyBackoff.Validate(); err != nil {
		return nil, fmt.Errorf("proxy backoff: %w", err)
	}
	if dependencies.Namespace == nil || dependencies.Firewall == nil ||
		dependencies.VPN == nil || dependencies.StartProxy == nil ||
		dependencies.Verifier == nil || dependencies.Publisher == nil ||
		dependencies.Sessions == nil || dependencies.Model == nil {
		return nil, errors.New("all worker controller dependencies are required")
	}
	return &Worker{
		spec: spec, deps: dependencies, commands: make(chan workerCommand),
	}, nil
}

func (w *Worker) Run(ctx context.Context) (runErr error) {
	if err := w.beginRun(); err != nil {
		return err
	}
	defer w.endRun()
	created := false
	var proxy *proxyRuntime
	var cancelProxyStart context.CancelFunc
	proxyStarting := false
	var cancelVPN context.CancelFunc
	var vpnDone <-chan error
	defer func() {
		cleanupErr := w.shutdown(
			created, &proxy, &cancelProxyStart, &proxyStarting, cancelVPN, vpnDone,
		)
		runErr = errors.Join(runErr, cleanupErr)
	}()

	if err := w.transition(workermodel.StateCreatingNamespace, "creating isolated network namespace", nil); err != nil {
		return err
	}
	if err := w.deps.Namespace.Create(ctx, w.spec.Allocation); err != nil {
		_ = w.transition(workermodel.StateFailed, "namespace creation failed", nil)
		return fmt.Errorf("worker %q create namespace: %w", w.spec.ID, err)
	}
	created = true

	if err := w.transition(workermodel.StateBootstrapping, "installing bootstrap kill switch", nil); err != nil {
		return err
	}
	bootstrapRules := w.spec.FirewallRules
	bootstrapRules.Mode = firewall.ModeBootstrap
	if err := w.deps.Firewall.Apply(ctx, w.spec.Allocation.Namespace, bootstrapRules); err != nil {
		_ = w.transition(workermodel.StateFailed, "bootstrap firewall failed", nil)
		return fmt.Errorf("worker %q install bootstrap firewall: %w", w.spec.ID, err)
	}

	if err := w.transition(workermodel.StateStartingOpenVPN, "starting OpenVPN supervisor", nil); err != nil {
		return err
	}
	vpnContext, vpnCancel := context.WithCancel(context.Background())
	cancelVPN = vpnCancel
	vpnEvents := make(chan VPNEvent, 16)
	vpnDoneChannel := make(chan error, 1)
	vpnDone = vpnDoneChannel
	go func() {
		vpnDoneChannel <- w.deps.VPN.Run(vpnContext, vpnEvents)
	}()
	if err := w.transition(workermodel.StateWaitingForTunnel, "waiting for verified VPN tunnel", nil); err != nil {
		return err
	}

	var vpnReady bool
	vpnGeneration := uint64(1)
	var epoch uint64
	var verificationEpoch uint64
	healthResults := make(chan verificationResult, 1)
	proxyStartResults := make(chan proxyStartResult, 1)
	healthTicker := time.NewTicker(w.spec.HealthInterval)
	defer healthTicker.Stop()
	var retryTimer *time.Timer
	var retryChannel <-chan time.Time
	proxyFailures := uint(0)
	successfulVerifications := 0

	stopRetry := func() {
		if retryTimer != nil {
			if !retryTimer.Stop() {
				select {
				case <-retryTimer.C:
				default:
				}
			}
		}
		retryTimer = nil
		retryChannel = nil
	}
	defer stopRetry()

	startVerification := func() {
		if verificationEpoch == epoch {
			return
		}
		verificationEpoch = epoch
		currentEpoch := epoch
		go func() {
			verifyContext, cancel := context.WithTimeout(ctx, w.spec.HealthTimeout)
			defer cancel()
			verification, err := w.deps.Verifier.Verify(verifyContext)
			result := verificationResult{
				epoch: currentEpoch, verification: verification, err: err,
			}
			select {
			case healthResults <- result:
			case <-ctx.Done():
			}
		}()
	}

	startProxy := func() error {
		stopRetry()
		if err := w.transition(workermodel.StateStartingProxy, "installing active firewall and starting proxy", nil); err != nil {
			return err
		}
		activeRules := w.spec.FirewallRules
		activeRules.Mode = firewall.ModeActive
		if err := w.deps.Firewall.Apply(ctx, w.spec.Allocation.Namespace, activeRules); err != nil {
			return fmt.Errorf("worker %q install active firewall: %w", w.spec.ID, err)
		}
		epoch++
		startEpoch := epoch
		proxyContext, cancelProxy := context.WithCancel(ctx)
		cancelProxyStart = cancelProxy
		proxyStarting = true
		go func() {
			running, err := w.deps.StartProxy(proxyContext)
			var runtime *proxyRuntime
			if err == nil && running == nil {
				err = errors.New("proxy starter returned no process")
			}
			if err == nil {
				done := make(chan error, 1)
				go func() {
					done <- running.Wait()
				}()
				runtime = &proxyRuntime{process: running, cancel: cancelProxy, done: done}
			} else {
				cancelProxy()
				err = fmt.Errorf("worker %q start proxy: %w", w.spec.ID, err)
			}
			result := proxyStartResult{epoch: startEpoch, runtime: runtime, err: err}
			select {
			case proxyStartResults <- result:
			case <-ctx.Done():
				if runtime != nil {
					_ = stopManaged(runtime, w.spec.StopTimeout)
				}
			}
		}()
		return nil
	}

	scheduleProxyRestart := func() error {
		delay, err := w.spec.ProxyBackoff.Duration(proxyFailures)
		if err != nil {
			return err
		}
		w.deps.Model.RecordProxyRestart()
		proxyFailures++
		stopRetry()
		retryTimer = time.NewTimer(delay)
		retryChannel = retryTimer.C
		return nil
	}

	for {
		var proxyDone <-chan error
		if proxy != nil {
			proxyDone = proxy.done
		}
		select {
		case <-ctx.Done():
			return nil

		case command := <-w.commands:
			switch command.kind {
			case commandSetDraining:
				w.deps.Model.SetDraining(command.draining)
				if !w.deps.Publisher.SetDraining(w.spec.ID, command.draining) {
					w.deps.Model.SetDraining(!command.draining)
					command.result <- fmt.Errorf("worker %q is not registered", w.spec.ID)
					continue
				}
				command.result <- nil
			case commandRestart:
				vpnReady = false
				err := w.deactivate(
					&proxy, &cancelProxyStart, &proxyStarting, &epoch,
					"operator requested restart",
				)
				if err == nil {
					w.deps.Model.RecordOpenVPNRestart()
					vpnGeneration = w.deps.VPN.Restart()
					err = w.moveToWaitingForTunnel()
				}
				command.result <- err
				if err != nil {
					return err
				}
			default:
				command.result <- errors.New("worker command is unsupported")
			}

		case event := <-vpnEvents:
			if event.Generation != vpnGeneration {
				continue
			}
			switch event.Type {
			case VPNTunnelReady:
				if vpnReady {
					continue
				}
				vpnReady = true
				proxyFailures = 0
				if proxy == nil && !proxyStarting {
					if err := startProxy(); err != nil {
						if deactivateErr := w.deactivate(
							&proxy, &cancelProxyStart, &proxyStarting, &epoch, err.Error(),
						); deactivateErr != nil {
							return errors.Join(err, deactivateErr)
						}
						if err := scheduleProxyRestart(); err != nil {
							return err
						}
					}
				}
			case VPNFailed:
				// The OpenVPN supervisor emits exactly one failure event for
				// each process/tunnel generation it is about to restart. Count
				// that cycle even if this worker was already withdrawn by an
				// earlier failed generation and needs no repeated teardown.
				w.deps.Model.RecordOpenVPNRestart()
				if !vpnReady && proxy == nil && !proxyStarting {
					continue
				}
				vpnReady = false
				if err := w.deactivate(
					&proxy, &cancelProxyStart, &proxyStarting, &epoch,
					"OpenVPN or tunnel failed",
				); err != nil {
					return errors.Join(event.Err, err)
				}
				if err := w.moveToWaitingForTunnel(); err != nil {
					return err
				}
			}

		case err := <-vpnDoneChannel:
			vpnDone = nil
			vpnReady = false
			if deactivateErr := w.deactivate(
				&proxy, &cancelProxyStart, &proxyStarting, &epoch,
				"OpenVPN supervisor stopped",
			); deactivateErr != nil {
				err = errors.Join(err, deactivateErr)
			}
			_ = w.transition(workermodel.StateFailed, "OpenVPN supervisor failed", nil)
			if err == nil {
				err = errors.New("OpenVPN supervisor stopped unexpectedly")
			}
			return fmt.Errorf("worker %q OpenVPN supervisor: %w", w.spec.ID, err)

		case result := <-proxyStartResults:
			if result.epoch != epoch || !proxyStarting || !vpnReady {
				if result.runtime != nil {
					_ = stopManaged(result.runtime, w.spec.StopTimeout)
				}
				continue
			}
			proxyStarting = false
			cancelProxyStart = nil
			if result.err != nil {
				if deactivateErr := w.deactivate(
					&proxy, &cancelProxyStart, &proxyStarting, &epoch, result.err.Error(),
				); deactivateErr != nil {
					return errors.Join(result.err, deactivateErr)
				}
				if err := scheduleProxyRestart(); err != nil {
					return err
				}
				continue
			}
			proxy = result.runtime
			successfulVerifications = 0
			verificationEpoch = 0
			if err := w.transition(workermodel.StateVerifyingEgress, "verifying worker egress", nil); err != nil {
				return err
			}
			startVerification()

		case err := <-proxyDone:
			proxy.cancel()
			proxy = nil
			if deactivateErr := w.deactivate(
				&proxy, &cancelProxyStart, &proxyStarting, &epoch, "worker proxy exited",
			); deactivateErr != nil {
				return errors.Join(err, deactivateErr)
			}
			if !vpnReady {
				if transitionErr := w.moveToWaitingForTunnel(); transitionErr != nil {
					return transitionErr
				}
				continue
			}
			if scheduleErr := scheduleProxyRestart(); scheduleErr != nil {
				return scheduleErr
			}

		case <-retryChannel:
			retryChannel = nil
			retryTimer = nil
			if !vpnReady || proxy != nil || proxyStarting {
				continue
			}
			if err := startProxy(); err != nil {
				if deactivateErr := w.deactivate(
					&proxy, &cancelProxyStart, &proxyStarting, &epoch, err.Error(),
				); deactivateErr != nil {
					return errors.Join(err, deactivateErr)
				}
				if err := scheduleProxyRestart(); err != nil {
					return err
				}
			}

		case result := <-healthResults:
			if result.epoch != epoch {
				continue
			}
			verificationEpoch = 0
			if result.err != nil {
				w.deps.Model.RecordHealthCheck(false)
				successfulVerifications = 0
				vpnReady = false
				if err := w.deactivate(
					&proxy, &cancelProxyStart, &proxyStarting, &epoch,
					"egress verification failed",
				); err != nil {
					return errors.Join(result.err, err)
				}
				w.deps.Model.RecordOpenVPNRestart()
				vpnGeneration = w.deps.VPN.Restart()
				if err := w.moveToWaitingForTunnel(); err != nil {
					return err
				}
				continue
			}
			w.deps.Model.RecordHealthCheck(true)
			if w.deps.Model.Snapshot().State == workermodel.StateVerifyingEgress {
				successfulVerifications++
				if successfulVerifications < w.spec.SuccessThreshold {
					continue
				}
				if err := w.publishHealthy(result.verification); err != nil {
					if deactivateErr := w.deactivate(
						&proxy, &cancelProxyStart, &proxyStarting, &epoch,
						"health publication failed",
					); deactivateErr != nil {
						return errors.Join(err, deactivateErr)
					}
					return err
				}
				proxyFailures = 0
			}

		case <-healthTicker.C:
			state := w.deps.Model.Snapshot().State
			if (state == workermodel.StateVerifyingEgress || state == workermodel.StateHealthy) &&
				verificationEpoch == 0 {
				startVerification()
			}
		}
	}
}

func (w *Worker) publishHealthy(verification Verification) error {
	evidence := workermodel.HealthEvidence{
		NamespaceExists:      true,
		VethUp:               true,
		OpenVPNAlive:         true,
		TunnelUp:             true,
		VPNRoutePresent:      true,
		ProxyAlive:           true,
		ProxyReachable:       true,
		TestRequestSucceeded: true,
		PublicIP:             verification.PublicIP,
		ExpectedIPConfigured: verification.ExpectedIPConfigured,
		ExpectedIPChecked:    verification.ExpectedIPChecked,
		ExpectedIPMatches:    verification.ExpectedIPMatches,
		UniquenessEnforced:   verification.UniquenessEnforced,
		UniquenessChecked:    verification.UniquenessChecked,
		PublicIPUnique:       verification.PublicIPUnique,
	}
	if err := w.transition(workermodel.StateHealthy, "complete egress verification succeeded", &evidence); err != nil {
		return err
	}
	candidate := w.spec.Candidate
	candidate.Healthy = true
	candidate.Draining = w.deps.Model.Snapshot().Draining
	if err := w.deps.Publisher.Upsert(candidate); err != nil {
		return fmt.Errorf("publish worker %q as healthy: %w", w.spec.ID, err)
	}
	return nil
}

func (w *Worker) SetDraining(ctx context.Context, draining bool) error {
	return w.sendCommand(ctx, workerCommand{kind: commandSetDraining, draining: draining})
}

func (w *Worker) Restart(ctx context.Context) error {
	return w.sendCommand(ctx, workerCommand{kind: commandRestart})
}

func (w *Worker) sendCommand(ctx context.Context, command workerCommand) error {
	if ctx == nil {
		return errors.New("worker command context is required")
	}
	command.result = make(chan error, 1)
	w.runMu.Lock()
	if !w.running {
		w.runMu.Unlock()
		return fmt.Errorf("worker %q controller is not running", w.spec.ID)
	}
	runDone := w.runDone
	select {
	case w.commands <- command:
		w.runMu.Unlock()
	case <-runDone:
		w.runMu.Unlock()
		return fmt.Errorf("worker %q controller stopped", w.spec.ID)
	case <-ctx.Done():
		w.runMu.Unlock()
		return ctx.Err()
	}
	select {
	case err := <-command.result:
		return err
	case <-runDone:
		return fmt.Errorf("worker %q controller stopped", w.spec.ID)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *Worker) beginRun() error {
	w.runMu.Lock()
	defer w.runMu.Unlock()
	if w.running {
		return fmt.Errorf("worker %q controller is already running", w.spec.ID)
	}
	w.running = true
	w.runDone = make(chan struct{})
	return nil
}

func (w *Worker) endRun() {
	w.runMu.Lock()
	defer w.runMu.Unlock()
	if w.running {
		close(w.runDone)
		w.running = false
	}
}

func (w *Worker) deactivate(
	proxy **proxyRuntime,
	cancelProxyStart *context.CancelFunc,
	proxyStarting *bool,
	epoch *uint64,
	reason string,
) error {
	w.deps.Publisher.SetHealthy(w.spec.ID, false)
	w.deps.Sessions.CloseWorkerSessions(w.spec.ID)
	w.deps.Verifier.Withdraw()
	if *cancelProxyStart != nil {
		(*cancelProxyStart)()
		*cancelProxyStart = nil
	}
	*proxyStarting = false
	*epoch++

	state := w.deps.Model.Snapshot().State
	if state != workermodel.StateRestarting && state != workermodel.StateFailed &&
		state != workermodel.StateStopping && state != workermodel.StateStopped {
		if err := w.transition(workermodel.StateDegraded, reason, nil); err != nil {
			return err
		}
	}

	strictRules := w.spec.FirewallRules
	strictRules.Mode = firewall.ModeStrict
	firewallContext, cancelFirewall := context.WithTimeout(context.Background(), w.spec.StopTimeout)
	firewallErr := w.deps.Firewall.Apply(
		firewallContext, w.spec.Allocation.Namespace, strictRules,
	)
	cancelFirewall()
	var processErr error
	if *proxy != nil {
		processErr = stopManaged(*proxy, w.spec.StopTimeout)
		*proxy = nil
	}
	if w.deps.Model.Snapshot().State == workermodel.StateDegraded {
		if err := w.transition(workermodel.StateRestarting, reason, nil); err != nil {
			return errors.Join(firewallErr, processErr, err)
		}
	}
	if firewallErr != nil {
		firewallErr = fmt.Errorf("worker %q apply strict firewall: %w", w.spec.ID, firewallErr)
	}
	return errors.Join(firewallErr, processErr)
}

func (w *Worker) moveToWaitingForTunnel() error {
	state := w.deps.Model.Snapshot().State
	if state == workermodel.StateWaitingForTunnel {
		return nil
	}
	if state == workermodel.StateRestarting {
		if err := w.transition(workermodel.StateStartingOpenVPN, "OpenVPN recovery in progress", nil); err != nil {
			return err
		}
	}
	if w.deps.Model.Snapshot().State == workermodel.StateStartingOpenVPN {
		return w.transition(workermodel.StateWaitingForTunnel, "waiting for recovered VPN tunnel", nil)
	}
	return nil
}

func (w *Worker) transition(
	next workermodel.State,
	reason string,
	evidence *workermodel.HealthEvidence,
) error {
	if err := w.deps.Model.Transition(next, reason, evidence); err != nil {
		return fmt.Errorf("worker %q transition to %s: %w", w.spec.ID, next, err)
	}
	return nil
}

func (w *Worker) shutdown(
	namespaceCreated bool,
	proxy **proxyRuntime,
	cancelProxyStart *context.CancelFunc,
	proxyStarting *bool,
	cancelVPN context.CancelFunc,
	vpnDone <-chan error,
) error {
	w.deps.Publisher.SetHealthy(w.spec.ID, false)
	w.deps.Sessions.CloseWorkerSessions(w.spec.ID)
	w.deps.Verifier.Withdraw()
	state := w.deps.Model.Snapshot().State
	if state != workermodel.StateStopping && state != workermodel.StateStopped {
		_ = w.transition(workermodel.StateStopping, "controller shutdown", nil)
	}
	var problems []error
	if namespaceCreated {
		strictRules := w.spec.FirewallRules
		strictRules.Mode = firewall.ModeStrict
		firewallContext, cancelFirewall := context.WithTimeout(context.Background(), w.spec.StopTimeout)
		if err := w.deps.Firewall.Apply(
			firewallContext, w.spec.Allocation.Namespace, strictRules,
		); err != nil {
			problems = append(problems, fmt.Errorf("apply shutdown firewall: %w", err))
		}
		cancelFirewall()
	}
	if *cancelProxyStart != nil {
		(*cancelProxyStart)()
		*cancelProxyStart = nil
	}
	*proxyStarting = false
	if *proxy != nil {
		if err := stopManaged(*proxy, w.spec.StopTimeout); err != nil {
			problems = append(problems, err)
		}
		*proxy = nil
	}
	if cancelVPN != nil {
		cancelVPN()
		if vpnDone != nil {
			select {
			case <-vpnDone:
			case <-time.After(w.spec.StopTimeout):
				problems = append(problems, errors.New("OpenVPN supervisor did not stop before timeout"))
			}
		}
	}
	if namespaceCreated {
		deleteContext, cancelDelete := context.WithTimeout(context.Background(), w.spec.StopTimeout)
		if err := w.deps.Namespace.Delete(
			deleteContext, w.spec.Allocation,
		); err != nil {
			problems = append(problems, fmt.Errorf("delete worker namespace: %w", err))
		}
		cancelDelete()
	}
	if w.deps.Model.Snapshot().State == workermodel.StateStopping {
		if err := w.transition(workermodel.StateStopped, "controller stopped", nil); err != nil {
			problems = append(problems, err)
		}
	}
	return errors.Join(problems...)
}

func stopManaged(runtime *proxyRuntime, timeout time.Duration) error {
	signalErr := runtime.process.Signal(syscall.SIGTERM)
	if signalErr != nil && !errors.Is(signalErr, os.ErrProcessDone) {
		_ = runtime.process.Kill()
		runtime.cancel()
		return fmt.Errorf("signal proxy process: %w", signalErr)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-runtime.done:
		runtime.cancel()
		return nil
	case <-timer.C:
		killErr := runtime.process.Kill()
		runtime.cancel()
		if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
			return fmt.Errorf("kill proxy process: %w", killErr)
		}
		select {
		case <-runtime.done:
			return nil
		case <-time.After(timeout):
			return errors.New("proxy process did not exit after forced termination")
		}
	}
}

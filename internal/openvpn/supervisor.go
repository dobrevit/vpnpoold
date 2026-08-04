package openvpn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/dobrevit/vpnpoold/internal/process"
	"github.com/dobrevit/vpnpoold/internal/worker"
)

type TunnelProbe interface {
	Check(context.Context) error
}

type StartFunc func(context.Context) (process.ManagedProcess, error)

type SupervisorConfig struct {
	StartupTimeout  time.Duration
	CheckInterval   time.Duration
	CheckTimeout    time.Duration
	StopTimeout     time.Duration
	CrashLoopWindow time.Duration
	CrashLoopLimit  int
	Backoff         worker.Backoff
}

type EventType string

const (
	EventStarting      EventType = "starting"
	EventWaitingTunnel EventType = "waiting_for_tunnel"
	EventTunnelReady   EventType = "tunnel_ready"
	EventTunnelFailed  EventType = "tunnel_failed"
	EventProcessExited EventType = "process_exited"
	EventRestarting    EventType = "restarting"
	EventStopping      EventType = "stopping"
)

type Event struct {
	Type         EventType
	PID          int
	RestartCount uint64
	Backoff      time.Duration
	Err          error
}

type Supervisor struct {
	Config     SupervisorConfig
	Start      StartFunc
	Probe      TunnelProbe
	Management ManagementWatcher
	OnEvent    func(Event)
}

func (s *Supervisor) Run(ctx context.Context) error {
	if err := s.validate(); err != nil {
		return err
	}
	var failures []time.Time
	var restartCount uint64
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		s.emit(Event{Type: EventStarting, RestartCount: restartCount})
		commandContext, cancelCommand := context.WithCancel(context.Background())
		running, err := s.Start(commandContext)
		if err != nil {
			cancelCommand()
			if failureErr := s.recordFailureAndWait(ctx, &failures, restartCount, err); failureErr != nil {
				return failureErr
			}
			restartCount++
			continue
		}

		exit := make(chan error, 1)
		go func() {
			exit <- running.Wait()
		}()
		managementContext, cancelManagement := context.WithCancel(context.Background())
		managementEvents := make(chan ManagementState, 16)
		managementDone := make(chan error, 1)
		go func() {
			managementDone <- s.Management.Watch(managementContext, managementEvents)
		}()
		s.emit(Event{Type: EventWaitingTunnel, PID: running.PID(), RestartCount: restartCount})

		ready, failure, stopped := s.waitForTunnel(
			ctx,
			running,
			exit,
			cancelCommand,
			managementEvents,
			managementDone,
			cancelManagement,
		)
		if stopped {
			return nil
		}
		if !ready {
			cancelManagement()
			if failureErr := s.recordFailureAndWait(ctx, &failures, restartCount, failure); failureErr != nil {
				return failureErr
			}
			restartCount++
			continue
		}

		failure, stopped = s.monitorTunnel(
			ctx,
			running,
			exit,
			cancelCommand,
			managementEvents,
			managementDone,
			cancelManagement,
			restartCount,
		)
		if stopped {
			return nil
		}
		if failureErr := s.recordFailureAndWait(ctx, &failures, restartCount, failure); failureErr != nil {
			return failureErr
		}
		restartCount++
	}
}

func (s *Supervisor) waitForTunnel(
	ctx context.Context,
	running process.ManagedProcess,
	exit <-chan error,
	cancelCommand context.CancelFunc,
	managementEvents <-chan ManagementState,
	managementDone <-chan error,
	cancelManagement context.CancelFunc,
) (ready bool, failure error, stopped bool) {
	startupTimer := time.NewTimer(s.Config.StartupTimeout)
	defer startupTimer.Stop()
	ticker := time.NewTicker(s.Config.CheckInterval)
	defer ticker.Stop()
	connected := false

	for {
		if connected {
			if err := s.checkTunnel(ctx); err != nil {
				goto wait
			}
			s.emit(Event{Type: EventTunnelReady, PID: running.PID()})
			return true, nil, false
		}
	wait:
		select {
		case <-ctx.Done():
			s.emit(Event{Type: EventStopping, PID: running.PID()})
			cancelManagement()
			_ = stopProcess(running, exit, cancelCommand, s.Config.StopTimeout)
			return false, nil, true
		case err := <-exit:
			cancelManagement()
			cancelCommand()
			failure = processExitError(err)
			s.emit(Event{Type: EventProcessExited, PID: running.PID(), Err: failure})
			return false, failure, false
		case state := <-managementEvents:
			switch state.Name {
			case managementStateConnected:
				if !state.Successful {
					failure = errors.New("OpenVPN management reported an unsuccessful connected state")
					s.emit(Event{Type: EventTunnelFailed, PID: running.PID(), Err: failure})
					cancelManagement()
					_ = stopProcess(running, exit, cancelCommand, s.Config.StopTimeout)
					return false, failure, false
				}
				connected = true
			case managementStateExiting:
				failure = errors.New("OpenVPN management reported exiting before tunnel readiness")
				s.emit(Event{Type: EventTunnelFailed, PID: running.PID(), Err: failure})
				cancelManagement()
				_ = stopProcess(running, exit, cancelCommand, s.Config.StopTimeout)
				return false, failure, false
			}
		case err := <-managementDone:
			if err == nil {
				err = errors.New("OpenVPN management watcher stopped unexpectedly")
			}
			failure = fmt.Errorf("OpenVPN management unavailable: %w", err)
			s.emit(Event{Type: EventTunnelFailed, PID: running.PID(), Err: failure})
			cancelManagement()
			_ = stopProcess(running, exit, cancelCommand, s.Config.StopTimeout)
			return false, failure, false
		case <-startupTimer.C:
			failure = errors.New("OpenVPN tunnel startup timed out")
			s.emit(Event{Type: EventTunnelFailed, PID: running.PID(), Err: failure})
			cancelManagement()
			_ = stopProcess(running, exit, cancelCommand, s.Config.StopTimeout)
			return false, failure, false
		case <-ticker.C:
		}
	}
}

func (s *Supervisor) monitorTunnel(
	ctx context.Context,
	running process.ManagedProcess,
	exit <-chan error,
	cancelCommand context.CancelFunc,
	managementEvents <-chan ManagementState,
	managementDone <-chan error,
	cancelManagement context.CancelFunc,
	restartCount uint64,
) (failure error, stopped bool) {
	ticker := time.NewTicker(s.Config.CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.emit(Event{Type: EventStopping, PID: running.PID(), RestartCount: restartCount})
			cancelManagement()
			_ = stopProcess(running, exit, cancelCommand, s.Config.StopTimeout)
			return nil, true
		case err := <-exit:
			cancelManagement()
			cancelCommand()
			failure = processExitError(err)
			s.emit(Event{Type: EventProcessExited, PID: running.PID(), RestartCount: restartCount, Err: failure})
			return failure, false
		case state := <-managementEvents:
			if state.Name != managementStateReconnecting &&
				state.Name != managementStateExiting &&
				(state.Name != managementStateConnected || state.Successful) {
				continue
			}
			failure = fmt.Errorf("OpenVPN management reported state %s", state.Name)
			s.emit(Event{Type: EventTunnelFailed, PID: running.PID(), RestartCount: restartCount, Err: failure})
			cancelManagement()
			if stopErr := stopProcess(running, exit, cancelCommand, s.Config.StopTimeout); stopErr != nil {
				failure = errors.Join(failure, stopErr)
			}
			return failure, false
		case err := <-managementDone:
			if err == nil {
				err = errors.New("OpenVPN management watcher stopped unexpectedly")
			}
			failure = fmt.Errorf("OpenVPN management unavailable: %w", err)
			s.emit(Event{Type: EventTunnelFailed, PID: running.PID(), RestartCount: restartCount, Err: failure})
			cancelManagement()
			if stopErr := stopProcess(running, exit, cancelCommand, s.Config.StopTimeout); stopErr != nil {
				failure = errors.Join(failure, stopErr)
			}
			return failure, false
		case <-ticker.C:
			if err := s.checkTunnel(ctx); err != nil {
				failure = fmt.Errorf("OpenVPN tunnel check failed: %w", err)
				s.emit(Event{Type: EventTunnelFailed, PID: running.PID(), RestartCount: restartCount, Err: failure})
				cancelManagement()
				if stopErr := stopProcess(running, exit, cancelCommand, s.Config.StopTimeout); stopErr != nil {
					failure = errors.Join(failure, stopErr)
				}
				return failure, false
			}
		}
	}
}

func (s *Supervisor) checkTunnel(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, s.Config.CheckTimeout)
	defer cancel()
	return s.Probe.Check(ctx)
}

func (s *Supervisor) recordFailureAndWait(
	ctx context.Context,
	failures *[]time.Time,
	restartCount uint64,
	cause error,
) error {
	now := time.Now()
	cutoff := now.Add(-s.Config.CrashLoopWindow)
	kept := (*failures)[:0]
	for _, failureTime := range *failures {
		if failureTime.After(cutoff) {
			kept = append(kept, failureTime)
		}
	}
	*failures = append(kept, now)
	if len(*failures) >= s.Config.CrashLoopLimit {
		return fmt.Errorf("OpenVPN rapid crash loop detected after %d failures: %w", len(*failures), cause)
	}
	delay, err := s.Config.Backoff.Duration(uint(len(*failures) - 1))
	if err != nil {
		return err
	}
	s.emit(Event{
		Type:         EventRestarting,
		RestartCount: restartCount + 1,
		Backoff:      delay,
		Err:          cause,
	})
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil
	case <-timer.C:
		return nil
	}
}

func (s *Supervisor) validate() error {
	if s.Start == nil {
		return errors.New("OpenVPN start function is required")
	}
	if s.Probe == nil {
		return errors.New("tunnel probe is required")
	}
	if s.Management == nil {
		return errors.New("OpenVPN management watcher is required")
	}
	if s.Config.StartupTimeout <= 0 || s.Config.CheckInterval <= 0 ||
		s.Config.CheckTimeout <= 0 || s.Config.StopTimeout <= 0 {
		return errors.New("supervisor timeouts and intervals must be positive")
	}
	if s.Config.CrashLoopWindow <= 0 || s.Config.CrashLoopLimit <= 0 {
		return errors.New("crash-loop window and limit must be positive")
	}
	return s.Config.Backoff.Validate()
}

func (s *Supervisor) emit(event Event) {
	if s.OnEvent != nil {
		s.OnEvent(event)
	}
}

func processExitError(err error) error {
	if err == nil {
		return errors.New("OpenVPN process exited unexpectedly")
	}
	return fmt.Errorf("OpenVPN process exited: %w", err)
}

func stopProcess(
	running process.ManagedProcess,
	exit <-chan error,
	cancelCommand context.CancelFunc,
	timeout time.Duration,
) error {
	signalErr := running.Signal(syscall.SIGTERM)
	if signalErr != nil && !errors.Is(signalErr, os.ErrProcessDone) {
		_ = running.Kill()
		cancelCommand()
		return fmt.Errorf("signal OpenVPN process: %w", signalErr)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-exit:
		cancelCommand()
		return nil
	case <-timer.C:
		killErr := running.Kill()
		cancelCommand()
		if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
			return fmt.Errorf("kill OpenVPN process after stop timeout: %w", killErr)
		}
		select {
		case <-exit:
		case <-time.After(timeout):
			return errors.New("OpenVPN process did not exit after forced termination")
		}
		return nil
	}
}

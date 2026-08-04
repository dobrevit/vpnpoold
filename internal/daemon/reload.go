package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

type RuntimeRun interface {
	Wait() error
}

type RuntimeGeneration interface {
	Start(context.Context) (*Running, error)
	Close() error
}

type ReloadCandidate struct {
	Runtime RuntimeGeneration
	Commit  func()
}

type ReloadPrepareFunc func(context.Context) (ReloadCandidate, error)

type GenerationSupervisor struct {
	Initial RuntimeGeneration
	Prepare ReloadPrepareFunc
	Logger  *slog.Logger
}

// Run keeps the current generation active while the next configuration is
// loaded, validated, resolved, and derived. Cutover happens only after
// preparation succeeds. The exact old generation is retained for rollback
// until the candidate has activated its firewall and listeners.
func (s GenerationSupervisor) Run(ctx context.Context, reload <-chan struct{}) (runErr error) {
	if ctx == nil || s.Initial == nil || s.Prepare == nil || s.Logger == nil {
		return errors.New("generation supervisor is not fully configured")
	}
	current := s.Initial
	running, cancelGeneration, err := startGeneration(ctx, current)
	if err != nil {
		_ = current.Close()
		return fmt.Errorf("start initial daemon generation: %w", err)
	}
	runningDone := waitForRun(running)
	defer func() {
		cancelGeneration()
		runErr = errors.Join(runErr, <-runningDone, current.Close())
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-runningDone:
			cancelGeneration()
			runningDone = closedRunResult(err)
			if ctx.Err() != nil {
				return nil
			}
			if err == nil {
				return errors.New("daemon generation stopped unexpectedly")
			}
			return fmt.Errorf("daemon generation stopped: %w", err)
		case <-reload:
			candidate, prepareErr := s.Prepare(ctx)
			if prepareErr != nil {
				if ctx.Err() != nil {
					return nil
				}
				s.Logger.Error("configuration reload rejected",
					slog.String("error", prepareErr.Error()),
				)
				continue
			}
			if candidate.Runtime == nil {
				s.Logger.Error("configuration reload rejected",
					slog.String("error", "reload preparation returned no runtime"),
				)
				continue
			}

			cancelGeneration()
			stopErr := <-runningDone
			if ctx.Err() != nil {
				_ = candidate.Runtime.Close()
				runningDone = closedRunResult(stopErr)
				return nil
			}
			if stopErr != nil {
				_ = candidate.Runtime.Close()
				s.Logger.Error("configuration reload cutover stopped; restoring prior generation",
					slog.String("error", stopErr.Error()),
				)
				running, cancelGeneration, err = startGeneration(ctx, current)
				if err != nil {
					runningDone = closedRunResult(nil)
					return errors.Join(
						fmt.Errorf("stop prior daemon generation: %w", stopErr),
						fmt.Errorf("restore prior daemon generation: %w", err),
					)
				}
				runningDone = waitForRun(running)
				continue
			}

			nextRunning, nextCancel, activateErr := startGeneration(ctx, candidate.Runtime)
			if activateErr != nil {
				_ = candidate.Runtime.Close()
				s.Logger.Error("configuration reload activation failed; restoring prior generation",
					slog.String("error", activateErr.Error()),
				)
				running, cancelGeneration, err = startGeneration(ctx, current)
				if err != nil {
					runningDone = closedRunResult(nil)
					return errors.Join(
						fmt.Errorf("activate candidate daemon generation: %w", activateErr),
						fmt.Errorf("restore prior daemon generation: %w", err),
					)
				}
				runningDone = waitForRun(running)
				continue
			}

			if closeErr := current.Close(); closeErr != nil {
				nextCancel()
				nextStopErr := nextRunning.Wait()
				_ = candidate.Runtime.Close()
				runningDone = closedRunResult(nil)
				return errors.Join(
					fmt.Errorf("retire prior daemon generation: %w", closeErr),
					nextStopErr,
				)
			}
			current = candidate.Runtime
			running = nextRunning
			cancelGeneration = nextCancel
			runningDone = waitForRun(running)
			if candidate.Commit != nil {
				candidate.Commit()
			}
			s.Logger.Info("configuration reload committed")
		}
	}
}

func startGeneration(
	parent context.Context,
	runtime RuntimeGeneration,
) (*Running, context.CancelFunc, error) {
	generationContext, cancel := context.WithCancel(parent)
	running, err := runtime.Start(generationContext)
	if err != nil {
		cancel()
		return nil, func() {}, err
	}
	return running, cancel, nil
}

func waitForRun(running RuntimeRun) <-chan error {
	result := make(chan error, 1)
	go func() {
		result <- running.Wait()
	}()
	return result
}

func closedRunResult(err error) <-chan error {
	result := make(chan error, 1)
	result <- err
	return result
}

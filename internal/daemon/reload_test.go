package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestGenerationSupervisorCommitsPreparedCandidate(t *testing.T) {
	initial := newFakeGeneration()
	next := newFakeGeneration()
	committed := make(chan struct{})
	reloads := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- (GenerationSupervisor{
			Initial: initial,
			Prepare: func(context.Context) (ReloadCandidate, error) {
				return ReloadCandidate{
					Runtime: next,
					Commit:  func() { close(committed) },
				}, nil
			},
			Logger: discardLogger(),
		}).Run(ctx, reloads)
	}()
	initial.waitForStarts(t, 1)
	reloads <- struct{}{}
	select {
	case <-committed:
	case <-time.After(time.Second):
		t.Fatal("candidate was not committed")
	}
	if initial.closeCount() != 1 {
		t.Fatalf("initial close count = %d, want 1", initial.closeCount())
	}
	if next.startCount() != 1 {
		t.Fatalf("candidate start count = %d, want 1", next.startCount())
	}
	cancel()
	if err := waitSupervisor(t, done); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if next.closeCount() != 1 {
		t.Fatalf("candidate close count = %d, want 1", next.closeCount())
	}
}

func TestGenerationSupervisorRollsBackActivationFailure(t *testing.T) {
	initial := newFakeGeneration()
	failed := newFakeGeneration()
	failed.startErr = errors.New("listener occupied")
	reloads := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- (GenerationSupervisor{
			Initial: initial,
			Prepare: func(context.Context) (ReloadCandidate, error) {
				return ReloadCandidate{Runtime: failed}, nil
			},
			Logger: discardLogger(),
		}).Run(ctx, reloads)
	}()
	initial.waitForStarts(t, 1)
	reloads <- struct{}{}
	initial.waitForStarts(t, 2)
	if failed.closeCount() != 1 {
		t.Fatalf("failed candidate close count = %d, want 1", failed.closeCount())
	}
	if initial.closeCount() != 0 {
		t.Fatalf("rollback runtime was prematurely closed")
	}
	cancel()
	if err := waitSupervisor(t, done); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestGenerationSupervisorRejectsPreparationWithoutStoppingCurrent(t *testing.T) {
	initial := newFakeGeneration()
	prepared := make(chan struct{})
	reloads := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- (GenerationSupervisor{
			Initial: initial,
			Prepare: func(context.Context) (ReloadCandidate, error) {
				close(prepared)
				return ReloadCandidate{}, errors.New("invalid replacement")
			},
			Logger: discardLogger(),
		}).Run(ctx, reloads)
	}()
	initial.waitForStarts(t, 1)
	reloads <- struct{}{}
	select {
	case <-prepared:
	case <-time.After(time.Second):
		t.Fatal("reload was not prepared")
	}
	if initial.startCount() != 1 || initial.closeCount() != 0 {
		t.Fatalf("current generation changed after rejected preparation")
	}
	cancel()
	if err := waitSupervisor(t, done); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

type fakeGeneration struct {
	mu       sync.Mutex
	starts   int
	closes   int
	startErr error
	started  chan struct{}
}

func newFakeGeneration() *fakeGeneration {
	return &fakeGeneration{started: make(chan struct{}, 8)}
}

func (g *fakeGeneration) Start(ctx context.Context) (*Running, error) {
	g.mu.Lock()
	g.starts++
	err := g.startErr
	g.mu.Unlock()
	g.started <- struct{}{}
	if err != nil {
		return nil, err
	}
	running := &Running{done: make(chan error, 1)}
	go func() {
		<-ctx.Done()
		running.done <- nil
	}()
	return running, nil
}

func (g *fakeGeneration) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closes++
	return nil
}

func (g *fakeGeneration) waitForStarts(t *testing.T, count int) {
	t.Helper()
	for g.startCount() < count {
		select {
		case <-g.started:
		case <-time.After(time.Second):
			t.Fatalf("generation did not reach start %d", count)
		}
	}
}

func (g *fakeGeneration) startCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.starts
}

func (g *fakeGeneration) closeCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closes
}

func waitSupervisor(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		t.Fatal("generation supervisor did not stop")
		return nil
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

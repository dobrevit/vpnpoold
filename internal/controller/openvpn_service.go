package controller

import (
	"context"
	"errors"
	"sync"

	"github.com/dobrevit/vpnpoold/internal/openvpn"
)

type SupervisorFactory func() *openvpn.Supervisor

// SupervisorService adapts the OpenVPN process/tunnel supervisor to the worker
// controller. Restart cancels the current supervised generation and starts a
// fresh one; readiness is never carried across generations.
type SupervisorService struct {
	Factory SupervisorFactory

	mu             sync.Mutex
	nextGeneration uint64
	restart        chan uint64
}

func NewSupervisorService(factory SupervisorFactory) (*SupervisorService, error) {
	if factory == nil {
		return nil, errors.New("OpenVPN supervisor factory is required")
	}
	return &SupervisorService{
		Factory:        factory,
		nextGeneration: 1,
		restart:        make(chan uint64, 1),
	}, nil
}

func (s *SupervisorService) Restart() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextGeneration++
	generation := s.nextGeneration
	select {
	case s.restart <- generation:
	default:
		// Coalesce pending restart requests, but preserve the newest generation.
		select {
		case <-s.restart:
		default:
		}
		select {
		case s.restart <- generation:
		default:
		}
	}
	return generation
}

func (s *SupervisorService) Run(ctx context.Context, events chan<- VPNEvent) error {
	if events == nil {
		return errors.New("VPN event channel is required")
	}
	generation := uint64(1)
	for {
		supervisor := s.Factory()
		if supervisor == nil {
			return errors.New("OpenVPN supervisor factory returned nil")
		}
		generationContext, cancel := context.WithCancel(ctx)
		currentGeneration := generation
		supervisor.OnEvent = func(event openvpn.Event) {
			var converted VPNEvent
			switch event.Type {
			case openvpn.EventTunnelReady:
				converted = VPNEvent{Type: VPNTunnelReady, Generation: currentGeneration}
			case openvpn.EventTunnelFailed, openvpn.EventProcessExited:
				converted = VPNEvent{Type: VPNFailed, Generation: currentGeneration, Err: event.Err}
			default:
				return
			}
			select {
			case events <- converted:
			case <-generationContext.Done():
			}
		}
		done := make(chan error, 1)
		go func() {
			done <- supervisor.Run(generationContext)
		}()

		select {
		case <-ctx.Done():
			cancel()
			<-done
			return nil
		case generation = <-s.restart:
			cancel()
			<-done
			continue
		case err := <-done:
			cancel()
			return err
		}
	}
}

package controller

import (
	"context"
	"errors"

	"github.com/dobrevit/vpnpoold/internal/openvpn"
)

type SupervisorFactory func() *openvpn.Supervisor

// SupervisorService adapts the OpenVPN process/tunnel supervisor to the worker
// controller. Restart cancels the current supervised generation and starts a
// fresh one; readiness is never carried across generations.
type SupervisorService struct {
	Factory SupervisorFactory
	restart chan struct{}
}

func NewSupervisorService(factory SupervisorFactory) (*SupervisorService, error) {
	if factory == nil {
		return nil, errors.New("OpenVPN supervisor factory is required")
	}
	return &SupervisorService{
		Factory: factory,
		restart: make(chan struct{}, 1),
	}, nil
}

func (s *SupervisorService) Restart() {
	select {
	case s.restart <- struct{}{}:
	default:
	}
}

func (s *SupervisorService) Run(ctx context.Context, events chan<- VPNEvent) error {
	if events == nil {
		return errors.New("VPN event channel is required")
	}
	for {
		supervisor := s.Factory()
		if supervisor == nil {
			return errors.New("OpenVPN supervisor factory returned nil")
		}
		generationContext, cancel := context.WithCancel(ctx)
		supervisor.OnEvent = func(event openvpn.Event) {
			var converted VPNEvent
			switch event.Type {
			case openvpn.EventTunnelReady:
				converted = VPNEvent{Type: VPNTunnelReady}
			case openvpn.EventTunnelFailed, openvpn.EventProcessExited:
				converted = VPNEvent{Type: VPNFailed, Err: event.Err}
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
		case <-s.restart:
			cancel()
			<-done
			continue
		case err := <-done:
			cancel()
			return err
		}
	}
}

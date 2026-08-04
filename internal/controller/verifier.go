package controller

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	"github.com/dobrevit/vpnpoold/internal/health"
)

type PublicIPChecker interface {
	Check(context.Context) (netip.Addr, error)
}

type PublicIPVerifier struct {
	WorkerID string
	Checker  PublicIPChecker
	Registry *health.Registry
	Policy   health.VerificationPolicy

	mu         sync.Mutex
	generation uint64
}

func (v *PublicIPVerifier) Verify(ctx context.Context) (Verification, error) {
	if v.WorkerID == "" || v.Checker == nil || v.Registry == nil {
		return Verification{}, errors.New("public-IP verifier is not fully configured")
	}
	v.mu.Lock()
	generation := v.generation
	v.mu.Unlock()
	observed, err := v.Checker.Check(ctx)
	if err != nil {
		return Verification{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if generation != v.generation {
		return Verification{}, errors.New("public-IP verification was superseded by worker withdrawal")
	}
	result, err := v.Registry.VerifyAndRecord(v.WorkerID, observed, v.Policy)
	if err != nil {
		return Verification{}, err
	}
	return Verification{
		PublicIP:          result.ObservedIP,
		ExpectedIPMatches: true,
		PublicIPUnique:    true,
	}, nil
}

// Withdraw invalidates in-flight checks before releasing this worker's public
// IP. The lock orders removal against VerifyAndRecord so a stale verification
// cannot repopulate the uniqueness registry after fail-closed withdrawal.
func (v *PublicIPVerifier) Withdraw() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.generation++
	if v.Registry != nil && v.WorkerID != "" {
		v.Registry.Remove(v.WorkerID)
	}
}

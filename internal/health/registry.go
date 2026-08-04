package health

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

type VerificationPolicy struct {
	ExpectedIP        netip.Addr
	EnforceUniqueness bool
}

type VerificationResult struct {
	ObservedIP           netip.Addr
	PreviousIP           netip.Addr
	Changed              bool
	ExpectedIPConfigured bool
	ExpectedIPChecked    bool
	ExpectedIPMatches    bool
	UniquenessEnforced   bool
	UniquenessChecked    bool
	PublicIPUnique       bool
}

type Registry struct {
	mu         sync.Mutex
	workers    map[string]netip.Addr
	hostWANIPs map[netip.Addr]struct{}
}

func NewRegistry() *Registry {
	return &Registry{
		workers: make(map[string]netip.Addr), hostWANIPs: make(map[netip.Addr]struct{}),
	}
}

func (r *Registry) VerifyAndRecord(
	workerID string,
	observed netip.Addr,
	policy VerificationPolicy,
) (VerificationResult, error) {
	if workerID == "" {
		return VerificationResult{}, errors.New("worker ID is required")
	}
	observed = observed.Unmap()
	if err := ValidatePublicIP(observed); err != nil {
		return VerificationResult{}, err
	}
	if policy.ExpectedIP.IsValid() && observed != policy.ExpectedIP.Unmap() {
		return VerificationResult{}, fmt.Errorf("observed public IP does not match the worker's expected IP")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, matchesHost := r.hostWANIPs[observed]; matchesHost {
		return VerificationResult{}, errors.New("observed public IP matches a host WAN IP; possible VPN leak")
	}
	if policy.EnforceUniqueness {
		for otherWorker, otherIP := range r.workers {
			if otherWorker != workerID && otherIP == observed {
				return VerificationResult{}, fmt.Errorf("observed public IP duplicates worker %q", otherWorker)
			}
		}
	}
	previous := r.workers[workerID]
	r.workers[workerID] = observed
	return VerificationResult{
		ObservedIP:           observed,
		PreviousIP:           previous,
		Changed:              previous.IsValid() && previous != observed,
		ExpectedIPConfigured: policy.ExpectedIP.IsValid(),
		ExpectedIPChecked:    policy.ExpectedIP.IsValid(),
		ExpectedIPMatches:    policy.ExpectedIP.IsValid(),
		UniquenessEnforced:   policy.EnforceUniqueness,
		UniquenessChecked:    policy.EnforceUniqueness,
		PublicIPUnique:       policy.EnforceUniqueness,
	}, nil
}

func (r *Registry) SetHostWANIPs(addresses []netip.Addr) error {
	next := make(map[netip.Addr]struct{}, len(addresses))
	for index, address := range addresses {
		address = address.Unmap()
		if err := ValidatePublicIP(address); err != nil {
			return fmt.Errorf("host WAN IP %d: %w", index, err)
		}
		next[address] = struct{}{}
	}
	if len(next) == 0 {
		return errors.New("at least one host WAN IP is required")
	}
	r.mu.Lock()
	r.hostWANIPs = next
	r.mu.Unlock()
	return nil
}

func (r *Registry) Remove(workerID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.workers, workerID)
}

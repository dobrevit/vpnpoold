package dispatcher

import (
	"errors"
	"net"
	"sync"

	"github.com/dobrevit/vpnpoold/internal/balance"
)

type Pool interface {
	Snapshot() []balance.Candidate
	Acquire(id string, generation uint64) (balance.Candidate, bool)
	Release(id string)
	ReportFailure(id string, generation uint64, err error) bool
}

type Registry struct {
	mu      sync.RWMutex
	workers map[string]balance.Candidate
}

func NewRegistry() *Registry {
	return &Registry{workers: make(map[string]balance.Candidate)}
}

func (r *Registry) Upsert(candidate balance.Candidate) error {
	if err := validateCandidate(candidate); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if current, exists := r.workers[candidate.ID]; exists {
		candidate.ActiveConnections = current.ActiveConnections
		candidate.Generation = current.Generation + 1
	} else {
		candidate.ActiveConnections = 0
		candidate.Generation = 1
	}
	r.workers[candidate.ID] = candidate
	return nil
}

func (r *Registry) SetHealthy(id string, healthy bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	candidate, exists := r.workers[id]
	if !exists {
		return false
	}
	candidate.Healthy = healthy
	candidate.Generation++
	r.workers[id] = candidate
	return true
}

func (r *Registry) SetDraining(id string, draining bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	candidate, exists := r.workers[id]
	if !exists {
		return false
	}
	candidate.Draining = draining
	candidate.Generation++
	r.workers[id] = candidate
	return true
}

func (r *Registry) Remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.workers, id)
}

func (r *Registry) Snapshot() []balance.Candidate {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]balance.Candidate, 0, len(r.workers))
	for _, candidate := range r.workers {
		result = append(result, candidate)
	}
	return result
}

func (r *Registry) Acquire(id string, generation uint64) (balance.Candidate, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	candidate, exists := r.workers[id]
	if !exists || candidate.Generation != generation || !candidate.Healthy || candidate.Draining {
		return balance.Candidate{}, false
	}
	candidate.ActiveConnections++
	r.workers[id] = candidate
	return candidate, true
}

func (r *Registry) Release(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	candidate, exists := r.workers[id]
	if !exists {
		return
	}
	if candidate.ActiveConnections > 0 {
		candidate.ActiveConnections--
	}
	r.workers[id] = candidate
}

func (r *Registry) ReportFailure(id string, generation uint64, _ error) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	candidate, exists := r.workers[id]
	if !exists || candidate.Generation != generation {
		return false
	}
	candidate.Healthy = false
	candidate.Generation++
	r.workers[id] = candidate
	return true
}

func validateCandidate(candidate balance.Candidate) error {
	if candidate.ID == "" {
		return errors.New("worker ID is required")
	}
	if _, _, err := net.SplitHostPort(candidate.Address); err != nil {
		return errors.New("worker address must be a host and port")
	}
	if candidate.Weight < 1 || candidate.Weight > 100 {
		return errors.New("worker weight must be between 1 and 100")
	}
	if candidate.ActiveConnections < 0 {
		return errors.New("worker active connections must not be negative")
	}
	return nil
}

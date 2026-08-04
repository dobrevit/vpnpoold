package worker

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

type State uint8

const (
	StateDisabled State = iota
	StateCreatingNamespace
	StateBootstrapping
	StateStartingOpenVPN
	StateWaitingForTunnel
	StateStartingProxy
	StateVerifyingEgress
	StateHealthy
	StateDegraded
	StateRestarting
	StateFailed
	StateStopping
	StateStopped
)

var stateNames = [...]string{
	"DISABLED",
	"CREATING_NAMESPACE",
	"BOOTSTRAPPING",
	"STARTING_OPENVPN",
	"WAITING_FOR_TUNNEL",
	"STARTING_PROXY",
	"VERIFYING_EGRESS",
	"HEALTHY",
	"DEGRADED",
	"RESTARTING",
	"FAILED",
	"STOPPING",
	"STOPPED",
}

func (s State) String() string {
	if int(s) >= len(stateNames) {
		return fmt.Sprintf("UNKNOWN_STATE_%d", s)
	}
	return stateNames[s]
}

type HealthEvidence struct {
	NamespaceExists      bool
	VethUp               bool
	OpenVPNAlive         bool
	TunnelUp             bool
	VPNRoutePresent      bool
	ProxyAlive           bool
	ProxyReachable       bool
	TestRequestSucceeded bool
	PublicIP             netip.Addr
	ExpectedIPConfigured bool
	ExpectedIPChecked    bool
	ExpectedIPMatches    bool
	UniquenessEnforced   bool
	UniquenessChecked    bool
	PublicIPUnique       bool
}

func (e HealthEvidence) Complete() bool {
	return e.NamespaceExists &&
		e.VethUp &&
		e.OpenVPNAlive &&
		e.TunnelUp &&
		e.VPNRoutePresent &&
		e.ProxyAlive &&
		e.ProxyReachable &&
		e.TestRequestSucceeded &&
		isPublicUnicast(e.PublicIP) &&
		(!e.ExpectedIPConfigured || (e.ExpectedIPChecked && e.ExpectedIPMatches)) &&
		(!e.UniquenessEnforced || (e.UniquenessChecked && e.PublicIPUnique))
}

type Snapshot struct {
	ID                   string
	State                State
	StateSince           time.Time
	Reason               string
	Enabled              bool
	EnabledOverridden    bool
	Draining             bool
	Available            bool
	Evidence             HealthEvidence
	LastHealthyAt        time.Time
	OpenVPNRestarts      uint64
	ProxyRestarts        uint64
	HealthCheckSuccesses uint64
	HealthCheckFailures  uint64
	ActiveConnections    int64
	ConnectionsTotal     uint64
	BackendSelections    uint64
	BytesFromClients     uint64
	BytesToClients       uint64
}

type Model struct {
	mu                   sync.RWMutex
	id                   string
	state                State
	stateSince           time.Time
	reason               string
	draining             bool
	evidence             HealthEvidence
	lastHealthyAt        time.Time
	openVPNRestarts      uint64
	proxyRestarts        uint64
	healthCheckSuccesses uint64
	healthCheckFailures  uint64
	now                  func() time.Time
}

func NewModel(id string) (*Model, error) {
	if id == "" {
		return nil, errors.New("worker id must not be empty")
	}
	return &Model{
		id:         id,
		state:      StateDisabled,
		stateSince: time.Now(),
		now:        time.Now,
	}, nil
}

// Transition changes selection eligibility atomically with state. In
// particular, any transition away from HEALTHY clears evidence before another
// dispatcher snapshot can observe the worker.
func (m *Model) Transition(next State, reason string, evidence *HealthEvidence) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !canTransition(m.state, next) {
		return fmt.Errorf("worker %q: invalid state transition %s -> %s", m.id, m.state, next)
	}
	if next == StateHealthy {
		if evidence == nil || !evidence.Complete() {
			return fmt.Errorf("worker %q: refusing HEALTHY transition without complete egress evidence", m.id)
		}
		m.evidence = *evidence
		m.lastHealthyAt = m.now()
	} else {
		m.evidence = HealthEvidence{}
	}
	m.state = next
	m.stateSince = m.now()
	m.reason = reason
	return nil
}

func (m *Model) RecordOpenVPNRestart() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.openVPNRestarts++
}

func (m *Model) RecordProxyRestart() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.proxyRestarts++
}

func (m *Model) RecordHealthCheck(successful bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if successful {
		m.healthCheckSuccesses++
		if m.state == StateHealthy {
			m.lastHealthyAt = m.now()
		}
		return
	}
	m.healthCheckFailures++
}

func (m *Model) SetDraining(draining bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.draining = draining
}

func (m *Model) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Snapshot{
		ID:                   m.id,
		State:                m.state,
		StateSince:           m.stateSince,
		Reason:               m.reason,
		Draining:             m.draining,
		Available:            m.state == StateHealthy && !m.draining && m.evidence.Complete(),
		Evidence:             m.evidence,
		LastHealthyAt:        m.lastHealthyAt,
		OpenVPNRestarts:      m.openVPNRestarts,
		ProxyRestarts:        m.proxyRestarts,
		HealthCheckSuccesses: m.healthCheckSuccesses,
		HealthCheckFailures:  m.healthCheckFailures,
	}
}

func canTransition(from, to State) bool {
	allowed, exists := transitions[from]
	if !exists {
		return false
	}
	return allowed[to]
}

var transitions = map[State]map[State]bool{
	StateDisabled: {
		StateCreatingNamespace: true,
		StateStopping:          true,
	},
	StateCreatingNamespace: {
		StateBootstrapping: true,
		StateFailed:        true,
		StateStopping:      true,
	},
	StateBootstrapping: {
		StateStartingOpenVPN: true,
		StateRestarting:      true,
		StateFailed:          true,
		StateStopping:        true,
	},
	StateStartingOpenVPN: {
		StateWaitingForTunnel: true,
		StateRestarting:       true,
		StateFailed:           true,
		StateStopping:         true,
	},
	StateWaitingForTunnel: {
		StateStartingProxy: true,
		StateDegraded:      true,
		StateRestarting:    true,
		StateFailed:        true,
		StateStopping:      true,
	},
	StateStartingProxy: {
		StateVerifyingEgress: true,
		StateDegraded:        true,
		StateRestarting:      true,
		StateFailed:          true,
		StateStopping:        true,
	},
	StateVerifyingEgress: {
		StateHealthy:    true,
		StateDegraded:   true,
		StateRestarting: true,
		StateFailed:     true,
		StateStopping:   true,
	},
	StateHealthy: {
		StateDegraded:   true,
		StateRestarting: true,
		StateStopping:   true,
	},
	StateDegraded: {
		StateVerifyingEgress: true,
		StateRestarting:      true,
		StateFailed:          true,
		StateStopping:        true,
	},
	StateRestarting: {
		StateCreatingNamespace: true,
		StateBootstrapping:     true,
		StateStartingOpenVPN:   true,
		StateStartingProxy:     true,
		StateFailed:            true,
		StateStopping:          true,
	},
	StateFailed: {
		StateRestarting: true,
		StateDisabled:   true,
		StateStopping:   true,
	},
	StateStopping: {
		StateStopped: true,
	},
	StateStopped: {
		StateCreatingNamespace: true,
		StateDisabled:          true,
	},
}

func isPublicUnicast(ip netip.Addr) bool {
	return ip.IsValid() &&
		ip.IsGlobalUnicast() &&
		!ip.IsPrivate() &&
		!ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsMulticast() &&
		!ip.IsUnspecified()
}

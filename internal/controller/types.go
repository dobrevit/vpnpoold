package controller

import (
	"context"
	"net/netip"
	"time"

	"github.com/dobrevit/vpnpoold/internal/balance"
	"github.com/dobrevit/vpnpoold/internal/firewall"
	"github.com/dobrevit/vpnpoold/internal/netutil"
	"github.com/dobrevit/vpnpoold/internal/process"
	"github.com/dobrevit/vpnpoold/internal/worker"
)

type NamespaceManager interface {
	Create(context.Context, netutil.Allocation) error
	Delete(context.Context, netutil.Allocation) error
}

type FirewallManager interface {
	Apply(context.Context, string, firewall.WorkerRules) error
}

type VPNEventType uint8

const (
	VPNTunnelReady VPNEventType = iota
	VPNFailed
)

type VPNEvent struct {
	Type       VPNEventType
	Generation uint64
	Err        error
}

// VPNService emits VPNTunnelReady only when process, tunnel interface, and VPN
// route checks have all passed. Restart must cause a fresh OpenVPN process and
// a new readiness event.
type VPNService interface {
	Run(context.Context, chan<- VPNEvent) error
	Restart() uint64
}

type ProxyStartFunc func(context.Context) (process.ManagedProcess, error)

type Verification struct {
	PublicIP             netip.Addr
	ExpectedIPConfigured bool
	ExpectedIPChecked    bool
	ExpectedIPMatches    bool
	UniquenessEnforced   bool
	UniquenessChecked    bool
	PublicIPUnique       bool
}

// Verifier must reach the proxy listener and complete a real external request
// through it. Process or port liveness alone is not a successful result.
type Verifier interface {
	Verify(context.Context) (Verification, error)
	Withdraw()
}

type AvailabilityPublisher interface {
	Upsert(balance.Candidate) error
	SetHealthy(string, bool) bool
	SetDraining(string, bool) bool
}

type SessionCloser interface {
	CloseWorkerSessions(string) int
}

type WorkerSpec struct {
	ID               string
	Allocation       netutil.Allocation
	FirewallRules    firewall.WorkerRules
	Candidate        balance.Candidate
	HealthInterval   time.Duration
	HealthTimeout    time.Duration
	SuccessThreshold int
	StopTimeout      time.Duration
	ProxyBackoff     worker.Backoff
}

type Dependencies struct {
	Namespace  NamespaceManager
	Firewall   FirewallManager
	VPN        VPNService
	StartProxy ProxyStartFunc
	Verifier   Verifier
	Publisher  AvailabilityPublisher
	Sessions   SessionCloser
	Model      *worker.Model
}

package worker

import (
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWorkerRequiresCompleteEvidenceBeforeHealthy(t *testing.T) {
	model := modelAtVerifying(t)
	evidence := completeEvidence()
	evidence.TestRequestSucceeded = false

	err := model.Transition(StateHealthy, "verification complete", &evidence)
	if err == nil || !strings.Contains(err.Error(), "complete egress evidence") {
		t.Fatalf("Transition() error = %v", err)
	}
	if snapshot := model.Snapshot(); snapshot.State != StateVerifyingEgress || snapshot.Available {
		t.Fatalf("snapshot after rejected transition = %+v", snapshot)
	}
}

func TestWorkerAvailabilityIsFailClosed(t *testing.T) {
	model := modelAtVerifying(t)
	evidence := completeEvidence()
	if err := model.Transition(StateHealthy, "verified", &evidence); err != nil {
		t.Fatalf("healthy transition: %v", err)
	}
	if !model.Snapshot().Available {
		t.Fatal("fully verified worker is unavailable")
	}

	model.SetDraining(true)
	if model.Snapshot().Available {
		t.Fatal("draining worker is available")
	}
	model.SetDraining(false)
	if !model.Snapshot().Available {
		t.Fatal("undrained healthy worker is unavailable")
	}

	if err := model.Transition(StateDegraded, "tunnel disappeared", nil); err != nil {
		t.Fatalf("degraded transition: %v", err)
	}
	snapshot := model.Snapshot()
	if snapshot.Available {
		t.Fatal("degraded worker is available")
	}
	if snapshot.Evidence.PublicIP.IsValid() {
		t.Fatalf("health evidence not cleared: %+v", snapshot.Evidence)
	}
}

func TestWorkerRejectsInvalidTransition(t *testing.T) {
	model, err := NewModel("worker-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := model.Transition(StateHealthy, "skip checks", ptrEvidence(completeEvidence())); err == nil {
		t.Fatal("DISABLED -> HEALTHY unexpectedly succeeded")
	}
}

func TestWorkerSnapshotIsRaceSafe(t *testing.T) {
	model := modelAtVerifying(t)
	if err := model.Transition(StateHealthy, "verified", ptrEvidence(completeEvidence())); err != nil {
		t.Fatal(err)
	}

	var wait sync.WaitGroup
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 100; iteration++ {
				model.SetDraining(iteration%2 == 0)
				model.RecordOpenVPNRestart()
				model.RecordProxyRestart()
				model.RecordHealthCheck(iteration%2 == 0)
				_ = model.Snapshot()
			}
		}()
	}
	wait.Wait()
}

func TestWorkerSnapshotRecordsBoundedOperationalCounters(t *testing.T) {
	model := modelAtVerifying(t)
	model.RecordOpenVPNRestart()
	model.RecordProxyRestart()
	model.RecordHealthCheck(true)
	model.RecordHealthCheck(false)
	if err := model.Transition(StateHealthy, "verified", ptrEvidence(completeEvidence())); err != nil {
		t.Fatal(err)
	}
	snapshot := model.Snapshot()
	if snapshot.OpenVPNRestarts != 1 ||
		snapshot.ProxyRestarts != 1 ||
		snapshot.HealthCheckSuccesses != 1 ||
		snapshot.HealthCheckFailures != 1 ||
		snapshot.LastHealthyAt.IsZero() {
		t.Fatalf("snapshot counters = %+v", snapshot)
	}
	later := snapshot.LastHealthyAt.Add(time.Minute)
	model.now = func() time.Time { return later }
	model.RecordHealthCheck(true)
	if got := model.Snapshot().LastHealthyAt; !got.Equal(later) {
		t.Fatalf("last healthy time = %v, want %v", got, later)
	}
}

func modelAtVerifying(t *testing.T) *Model {
	t.Helper()
	model, err := NewModel("worker-1")
	if err != nil {
		t.Fatal(err)
	}
	path := []State{
		StateCreatingNamespace,
		StateBootstrapping,
		StateStartingOpenVPN,
		StateWaitingForTunnel,
		StateStartingProxy,
		StateVerifyingEgress,
	}
	for _, state := range path {
		if err := model.Transition(state, "test", nil); err != nil {
			t.Fatalf("transition to %s: %v", state, err)
		}
	}
	return model
}

func completeEvidence() HealthEvidence {
	return HealthEvidence{
		NamespaceExists:      true,
		VethUp:               true,
		OpenVPNAlive:         true,
		TunnelUp:             true,
		VPNRoutePresent:      true,
		ProxyAlive:           true,
		ProxyReachable:       true,
		TestRequestSucceeded: true,
		PublicIP:             netip.MustParseAddr("8.8.8.8"),
		ExpectedIPMatches:    true,
		PublicIPUnique:       true,
	}
}

func TestHealthEvidenceRequiresConfiguredChecksToHaveSucceeded(t *testing.T) {
	evidence := completeEvidence()
	evidence.ExpectedIPConfigured = true
	evidence.ExpectedIPChecked = false
	if evidence.Complete() {
		t.Fatal("evidence was complete without configured expected-IP check")
	}
	evidence.ExpectedIPChecked = true
	evidence.ExpectedIPMatches = true
	evidence.UniquenessEnforced = true
	evidence.UniquenessChecked = false
	if evidence.Complete() {
		t.Fatal("evidence was complete without enforced uniqueness check")
	}
	evidence.UniquenessChecked = true
	evidence.PublicIPUnique = true
	if !evidence.Complete() {
		t.Fatal("complete required evidence was rejected")
	}
}

func ptrEvidence(evidence HealthEvidence) *HealthEvidence {
	return &evidence
}

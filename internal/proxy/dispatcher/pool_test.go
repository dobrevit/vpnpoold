package dispatcher

import (
	"errors"
	"testing"

	"github.com/dobrevit/vpnpoold/internal/balance"
)

func TestRegistryAcquireRechecksEligibilityAndTracksSessions(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Upsert(balance.Candidate{
		ID:      "worker-1",
		Address: "10.0.0.2:1081",
		Weight:  1,
		Healthy: true,
	}); err != nil {
		t.Fatal(err)
	}
	snapshot := registry.Snapshot()[0]
	acquired, ok := registry.Acquire(snapshot.ID, snapshot.Generation)
	if !ok || acquired.ActiveConnections != 1 {
		t.Fatalf("Acquire() = %+v, %t", acquired, ok)
	}
	registry.Release(snapshot.ID)
	if active := registry.Snapshot()[0].ActiveConnections; active != 0 {
		t.Fatalf("active connections = %d", active)
	}

	stale := registry.Snapshot()[0]
	registry.SetDraining(stale.ID, true)
	if _, ok := registry.Acquire(stale.ID, stale.Generation); ok {
		t.Fatal("stale selection acquired after drain")
	}
}

func TestRegistryFailureIsImmediateAndGenerationSafe(t *testing.T) {
	registry := NewRegistry()
	candidate := balance.Candidate{
		ID:      "worker-1",
		Address: "10.0.0.2:1081",
		Weight:  1,
		Healthy: true,
	}
	if err := registry.Upsert(candidate); err != nil {
		t.Fatal(err)
	}
	first := registry.Snapshot()[0]
	registry.ReportFailure(first.ID, first.Generation, errors.New("proxy unreachable"))
	failed := registry.Snapshot()[0]
	if failed.Healthy {
		t.Fatal("worker remained healthy after reported proxy failure")
	}

	registry.SetHealthy(first.ID, true)
	registry.ReportFailure(first.ID, first.Generation, errors.New("stale failure"))
	if !registry.Snapshot()[0].Healthy {
		t.Fatal("stale generation failure disabled recovered worker")
	}
}

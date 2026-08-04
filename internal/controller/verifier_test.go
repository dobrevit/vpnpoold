package controller

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/dobrevit/vpnpoold/internal/health"
)

func TestPublicIPVerifierAppliesRegistryPolicy(t *testing.T) {
	registry := health.NewRegistry()
	if err := registry.SetHostWANIPs([]netip.Addr{netip.MustParseAddr("1.1.1.1")}); err != nil {
		t.Fatal(err)
	}
	verifier := &PublicIPVerifier{
		WorkerID: "worker-1",
		Checker:  fixedIPChecker{address: netip.MustParseAddr("8.8.8.8")},
		Registry: registry,
	}
	result, err := verifier.Verify(context.Background())
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.PublicIP.String() != "8.8.8.8" ||
		result.ExpectedIPConfigured || result.ExpectedIPChecked || result.ExpectedIPMatches ||
		result.UniquenessEnforced || result.UniquenessChecked || result.PublicIPUnique {
		t.Fatalf("verification = %+v", result)
	}

	verifier.Checker = fixedIPChecker{address: netip.MustParseAddr("1.1.1.1")}
	if _, err := verifier.Verify(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "VPN leak") {
		t.Fatalf("host leak error = %v", err)
	}
}

func TestPublicIPVerifierWithdrawalReleasesAndInvalidatesAddress(t *testing.T) {
	registry := health.NewRegistry()
	checker := &blockingIPChecker{
		address: netip.MustParseAddr("8.8.8.8"),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	first := &PublicIPVerifier{
		WorkerID: "worker-1", Checker: checker, Registry: registry,
		Policy: health.VerificationPolicy{EnforceUniqueness: true},
	}
	done := make(chan error, 1)
	go func() {
		_, err := first.Verify(context.Background())
		done <- err
	}()
	<-checker.started
	first.Withdraw()
	close(checker.release)
	if err := <-done; err == nil || !strings.Contains(err.Error(), "superseded") {
		t.Fatalf("stale Verify() error = %v", err)
	}

	second := &PublicIPVerifier{
		WorkerID: "worker-2",
		Checker:  fixedIPChecker{address: netip.MustParseAddr("8.8.8.8")},
		Registry: registry,
		Policy:   health.VerificationPolicy{EnforceUniqueness: true},
	}
	if _, err := second.Verify(context.Background()); err != nil {
		t.Fatalf("replacement worker Verify() error = %v", err)
	}
	second.Withdraw()
}

type fixedIPChecker struct {
	address netip.Addr
	err     error
}

type blockingIPChecker struct {
	address netip.Addr
	started chan struct{}
	release chan struct{}
}

func (c *blockingIPChecker) Check(context.Context) (netip.Addr, error) {
	close(c.started)
	<-c.release
	return c.address, nil
}

func (c fixedIPChecker) Check(context.Context) (netip.Addr, error) {
	return c.address, c.err
}

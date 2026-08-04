//go:build integration && linux

package integration_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/dobrevit/vpnpoold/internal/firewall"
	"github.com/dobrevit/vpnpoold/internal/namespace"
	"github.com/dobrevit/vpnpoold/internal/netutil"
	"github.com/dobrevit/vpnpoold/internal/process"
)

func TestNamespaceLifecycleAndStrictKillSwitch(t *testing.T) {
	requirePrivilegedIntegration(t)
	ipPath := requireBinary(t, "ip")
	nftPath := requireBinary(t, "nft")
	runner := process.OSRunner{}
	allocator, err := netutil.NewAllocator(netip.MustParsePrefix("10.254.252.0/24"), 30)
	if err != nil {
		t.Fatal(err)
	}
	allocation, err := allocator.Allocate(0, "integration-worker", "vpnpooltest")
	if err != nil {
		t.Fatal(err)
	}

	namespaceManager, err := namespace.NewManager(runner, ipPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = namespaceManager.Delete(context.Background(), allocation)
	t.Cleanup(func() {
		if err := namespaceManager.Delete(context.Background(), allocation); err != nil {
			t.Errorf("cleanup namespace: %v", err)
		}
	})
	if err := namespaceManager.Create(context.Background(), allocation); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	firewallManager, err := firewall.NewManager(runner, ipPath, nftPath)
	if err != nil {
		t.Fatal(err)
	}
	rules := firewall.WorkerRules{
		Mode:            firewall.ModeStrict,
		VethInterface:   allocation.NamespaceVeth,
		TunnelInterface: "tun0",
		HostAddress:     allocation.HostAddress.Addr(),
		OpenVPNEndpoints: []firewall.Endpoint{{
			Address:  netip.MustParseAddr("198.51.100.10"),
			Protocol: "udp",
			Port:     1194,
		}},
	}
	if err := firewallManager.Apply(context.Background(), allocation.Namespace, rules); err != nil {
		t.Fatalf("apply strict firewall: %v", err)
	}

	result, err := runner.Run(context.Background(), process.Command{
		Path: ipPath,
		Args: []string{"netns", "exec", allocation.Namespace, nftPath, "list", "table", "inet", "vpnpoold"},
	})
	if err != nil {
		t.Fatalf("list namespace firewall: %v: %s", err, result.Stderr)
	}
	if !strings.Contains(result.Stdout, "policy drop") {
		t.Fatalf("namespace firewall is not default-drop:\n%s", result.Stdout)
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(allocation.HostAddress.Addr().String(), "0"))
	if err != nil {
		t.Fatalf("listen on host veth: %v", err)
	}
	defer listener.Close()

	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err = runner.Run(ctx, process.Command{
		Path: ipPath,
		Args: []string{
			"netns", "exec", allocation.Namespace,
			testBinary, "-test.run=TestNamespaceDialHelper", "--", listener.Addr().String(),
		},
		Env: []string{"VPNPOOLD_DIAL_HELPER=1"},
	})
	if err != nil {
		t.Fatalf("strict-mode dial check failed: %v: %s", err, result.Stderr)
	}
	if strings.TrimSpace(result.Stdout) != "BLOCKED" {
		t.Fatalf("strict firewall allowed direct namespace egress: %q", result.Stdout)
	}
}

func TestNamespaceDialHelper(t *testing.T) {
	if os.Getenv("VPNPOOLD_DIAL_HELPER") != "1" {
		return
	}
	address := os.Args[len(os.Args)-1]
	connection, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
	if err != nil {
		fmt.Print("BLOCKED")
		os.Exit(0)
	}
	_ = connection.Close()
	fmt.Print("ALLOWED")
	os.Exit(9)
}

func requirePrivilegedIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("VPNPOOLD_INTEGRATION") != "1" {
		t.Skip("set VPNPOOLD_INTEGRATION=1 to run privileged integration tests")
	}
	if os.Geteuid() != 0 {
		t.Skip("privileged integration tests require root")
	}
}

func requireBinary(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is required: %v", name, err)
	}
	return path
}

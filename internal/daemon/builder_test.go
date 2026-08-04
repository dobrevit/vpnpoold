package daemon

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dobrevit/vpnpoold/internal/config"
	"github.com/dobrevit/vpnpoold/internal/openvpn"
	"github.com/dobrevit/vpnpoold/internal/process"
	"github.com/dobrevit/vpnpoold/internal/worker"
)

func TestBuilderPreparesRuntimeWithoutPrivilegedMutation(t *testing.T) {
	cfg, source := validDaemonConfig(t)
	runner := &countingRunner{}
	runtime, err := (Builder{
		Runner: runner, Starter: unusedStarter{},
		Resolver: fixedResolver{
			"vpn.example": {
				netip.MustParseAddr("2001:db8::10"),
				netip.MustParseAddr("198.51.100.10"),
			},
		},
		ProfileReader: openvpn.OSProfileReader{},
		IPBinary:      "/usr/sbin/ip", NFTBinary: "/usr/sbin/nft",
		DaemonBinary: "/usr/sbin/vpnpoold",
	}).Build(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	defer runtime.Close()

	if runner.calls != 0 {
		t.Fatalf("Build() performed %d privileged command(s)", runner.calls)
	}
	if len(runtime.workers) != 1 {
		t.Fatalf("workers = %d, want 1", len(runtime.workers))
	}
	if err := runtime.SetInitialWorkerDraining("worker-1", true); err != nil {
		t.Fatalf("SetInitialWorkerDraining() error = %v", err)
	}
	if snapshots := runtime.WorkerSnapshots(); len(snapshots) != 1 || !snapshots[0].Draining {
		t.Fatalf("initial draining state was not retained: %+v", snapshots)
	}
	if got := runtime.hostRules.OpenVPNEndpoints; len(got) != 1 ||
		got[0] != netip.MustParseAddr("198.51.100.10") {
		t.Fatalf("host endpoints = %v", got)
	}
	derivedPath := filepath.Join(runtime.generationDirectory, "worker-1.ovpn")
	derived, err := os.ReadFile(derivedPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(derived), "vpn.example") ||
		!strings.Contains(string(derived), "remote 198.51.100.10 1194 udp") {
		t.Fatalf("unexpected derived profile: %s", derived)
	}
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(original) != "client\nremote vpn.example 1194 udp\n" {
		t.Fatal("source profile changed")
	}
}

func TestBuilderRetainsInitiallyDisabledWorkers(t *testing.T) {
	cfg, _ := validDaemonConfig(t)
	cfg.Workers[0].Enabled = false
	runtime, err := (Builder{
		Runner: &countingRunner{}, Starter: unusedStarter{},
		Resolver: fixedResolver{
			"vpn.example": {netip.MustParseAddr("198.51.100.10")},
		},
		ProfileReader: openvpn.OSProfileReader{},
		IPBinary:      "/usr/sbin/ip", NFTBinary: "/usr/sbin/nft",
		DaemonBinary: "/usr/sbin/vpnpoold",
	}).Build(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	defer runtime.Close()

	snapshots := runtime.WorkerSnapshots()
	if len(snapshots) != 1 {
		t.Fatalf("workers = %d, want 1", len(snapshots))
	}
	if snapshots[0].Enabled {
		t.Fatalf("disabled worker snapshot = %+v", snapshots[0])
	}
	if snapshots[0].State != worker.StateDisabled {
		t.Fatalf("disabled worker state = %s", snapshots[0].State)
	}
}

func TestBuilderPreparesManagementUsernamePasswordWorker(t *testing.T) {
	cfg, source := validDaemonConfig(t)
	credentials := filepath.Join(filepath.Dir(source), "credentials")
	if err := os.WriteFile(credentials, []byte("alice\nsecret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		source,
		[]byte("client\nauth-user-pass source-secret-path\nremote vpn.example 1194 udp\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	cfg.Workers[0].CredentialsFile = credentials
	cfg.Workers[0].Management.UsernamePassword = true
	runtime, err := (Builder{
		Runner: &countingRunner{}, Starter: unusedStarter{},
		Resolver: fixedResolver{
			"vpn.example": {netip.MustParseAddr("198.51.100.10")},
		},
		ProfileReader: openvpn.OSProfileReader{},
		IPBinary:      "/usr/sbin/ip", NFTBinary: "/usr/sbin/nft",
		DaemonBinary: "/usr/sbin/vpnpoold",
	}).Build(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	defer runtime.Close()
	derived, err := os.ReadFile(filepath.Join(runtime.generationDirectory, "worker-1.ovpn"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(derived), "\nauth-user-pass\n") ||
		strings.Contains(string(derived), credentials) ||
		strings.Contains(string(derived), "source-secret-path") {
		t.Fatalf("unexpected derived profile:\n%s", derived)
	}
}

func TestBuilderRollbackRemovesDerivedGeneration(t *testing.T) {
	cfg, source := validDaemonConfig(t)
	if err := os.WriteFile(source, []byte("<connection>\nremote vpn.example 1194\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := (Builder{
		Runner: &countingRunner{}, Starter: unusedStarter{},
		Resolver: fixedResolver{
			"vpn.example": {netip.MustParseAddr("198.51.100.10")},
		},
		ProfileReader: openvpn.OSProfileReader{},
		IPBinary:      "/usr/sbin/ip", NFTBinary: "/usr/sbin/nft",
		DaemonBinary: "/usr/sbin/vpnpoold",
	}).Build(context.Background(), cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "unterminated connection") {
		t.Fatalf("Build() error = %v", err)
	}
	entries, readErr := os.ReadDir(cfg.Runtime.RunDir)
	if errors.Is(readErr, os.ErrNotExist) {
		return
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("runtime rollback left files: %v", entries)
	}
}

func TestBuilderRequiresOrDiscoversHostPublicIP(t *testing.T) {
	cfg, _ := validDaemonConfig(t)
	cfg.Health.HostPublicIPs = nil
	base := Builder{
		Runner: &countingRunner{}, Starter: unusedStarter{},
		Resolver: fixedResolver{
			"vpn.example": {netip.MustParseAddr("198.51.100.10")},
		},
		ProfileReader: openvpn.OSProfileReader{},
		IPBinary:      "/usr/sbin/ip", NFTBinary: "/usr/sbin/nft",
		DaemonBinary: "/usr/sbin/vpnpoold",
	}
	if _, err := base.Build(context.Background(), cfg, nil); err == nil ||
		!strings.Contains(err.Error(), "host public-IP discovery") {
		t.Fatalf("Build() without host discovery error = %v", err)
	}
	base.HostIPChecker = staticIPChecker{address: netip.MustParseAddr("8.8.8.8")}
	runtime, err := base.Build(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Build() with host discovery error = %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBuilderSupportsOpenVPNConnectionBlocks(t *testing.T) {
	cfg, source := validDaemonConfig(t)
	profile := "client\n<connection>\nproto tcp-client\nremote tcp.example 443\n</connection>\n"
	if err := os.WriteFile(source, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime, err := (Builder{
		Runner: &countingRunner{}, Starter: unusedStarter{},
		Resolver: fixedResolver{
			"tcp.example": {netip.MustParseAddr("198.51.100.44")},
		},
		ProfileReader: openvpn.OSProfileReader{},
		IPBinary:      "/usr/sbin/ip", NFTBinary: "/usr/sbin/nft",
		DaemonBinary: "/usr/sbin/vpnpoold",
	}).Build(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	defer runtime.Close()
	derived, err := os.ReadFile(filepath.Join(runtime.generationDirectory, "worker-1.ovpn"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(derived), "<connection>\nproto tcp-client\nremote 198.51.100.44 443 tcp\n</connection>") {
		t.Fatalf("connection block was not preserved:\n%s", derived)
	}
}

func validDaemonConfig(t *testing.T) (*config.Config, string) {
	t.Helper()
	root, err := os.MkdirTemp("", "vpnpoold-daemon-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	profiles := filepath.Join(root, "profiles")
	if err := os.Mkdir(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(profiles, "worker.ovpn")
	if err := os.WriteFile(source, []byte("client\nremote vpn.example 1194 udp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	openvpnBinary := filepath.Join(root, "openvpn")
	if err := os.WriteFile(openvpnBinary, []byte("executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Runtime.RunDir = filepath.Join(root, "run")
	cfg.Runtime.StateDir = filepath.Join(root, "state")
	cfg.OpenVPN.Binary = openvpnBinary
	cfg.OpenVPN.ProfilesDir = profiles
	cfg.Network.HostUplinkInterface = "eth0"
	cfg.Health.IPCheckURL = "https://ip.test-domain.dev/ip"
	cfg.Health.HostPublicIPs = []string{"8.8.8.8"}
	cfg.Workers = []config.Worker{{
		ID: "worker-1", Config: "worker.ovpn", Enabled: true, Weight: 1,
	}}
	return &cfg, source
}

type fixedResolver map[string][]netip.Addr

func (r fixedResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	addresses, exists := r[host]
	if !exists {
		return nil, errors.New("not found")
	}
	return addresses, nil
}

type countingRunner struct {
	calls int
}

func (r *countingRunner) Run(context.Context, process.Command) (process.Result, error) {
	r.calls++
	return process.Result{}, nil
}

type unusedStarter struct{}

func (unusedStarter) Start(context.Context, process.Command) (process.ManagedProcess, error) {
	return nil, errors.New("unexpected process start")
}

type staticIPChecker struct {
	address netip.Addr
}

func (c staticIPChecker) Check(context.Context) (netip.Addr, error) {
	return c.address, nil
}

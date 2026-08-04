package firewall

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/dobrevit/vpnpoold/internal/process"
)

func TestRemoveHostIsIdempotent(t *testing.T) {
	tests := []struct {
		name       string
		listOutput string
		wantArgs   [][]string
	}{
		{
			name:       "absent",
			listOutput: "table inet unrelated\n",
			wantArgs:   [][]string{{"list", "tables"}},
		},
		{
			name:       "present",
			listOutput: "table inet unrelated\ntable inet vpnpoold_host\n",
			wantArgs: [][]string{
				{"list", "tables"},
				{"delete", "table", "inet", "vpnpoold_host"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &hostCleanupRunner{results: []process.Result{{Stdout: test.listOutput}}}
			manager, err := NewManager(runner, "/usr/sbin/ip", "/usr/sbin/nft")
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.RemoveHost(context.Background()); err != nil {
				t.Fatalf("RemoveHost() error = %v", err)
			}
			if !reflect.DeepEqual(runner.args, test.wantArgs) {
				t.Fatalf("commands = %#v, want %#v", runner.args, test.wantArgs)
			}
		})
	}
}

func validWorkerRules() WorkerRules {
	return WorkerRules{
		Mode:            ModeStrict,
		VethInterface:   "vpn1234567890",
		TunnelInterface: "tun0",
		HostAddress:     netip.MustParseAddr("10.231.0.1"),
		ProxyPort:       1081,
		OpenVPNEndpoints: []Endpoint{{
			Address:  netip.MustParseAddr("198.51.100.10"),
			Protocol: "udp",
			Port:     1194,
		}},
	}
}

func validHostRules() HostRules {
	return HostRules{
		WorkerSubnet:     netip.MustParsePrefix("10.231.0.0/16"),
		UplinkInterface:  "eth0",
		WorkerVeths:      []string{"vph1234567890"},
		OpenVPNEndpoints: []netip.Addr{netip.MustParseAddr("198.51.100.10")},
	}
}

func TestRemoveHostReportsListFailure(t *testing.T) {
	runner := &hostCleanupRunner{errors: []error{errors.New("denied")}}
	manager, err := NewManager(runner, "/usr/sbin/ip", "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RemoveHost(context.Background()); err == nil {
		t.Fatal("RemoveHost() unexpectedly succeeded")
	}
}

func TestApplyFailsClosedWhenTableInspectionFails(t *testing.T) {
	tests := []struct {
		name  string
		apply func(*Manager) error
	}{
		{
			name: "namespace",
			apply: func(manager *Manager) error {
				return manager.Apply(context.Background(), "vpnpool-1234567890", validWorkerRules())
			},
		},
		{
			name: "host",
			apply: func(manager *Manager) error {
				return manager.ApplyHost(context.Background(), validHostRules())
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &hostCleanupRunner{errors: []error{errors.New("probe unavailable")}}
			manager, err := NewManager(runner, "/usr/sbin/ip", "/usr/sbin/nft")
			if err != nil {
				t.Fatal(err)
			}
			if err := test.apply(manager); err == nil || len(runner.args) != 1 {
				t.Fatalf("Apply() error = %v, commands = %#v", err, runner.args)
			}
		})
	}
}

func TestApplyAtomicallyReplacesOnlyAnExistingTable(t *testing.T) {
	tests := []struct {
		name       string
		listOutput string
		wantDelete bool
	}{
		{name: "absent", listOutput: "table inet unrelated\n"},
		{name: "present", listOutput: "table inet vpnpoold\n", wantDelete: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &hostCleanupRunner{results: []process.Result{{Stdout: test.listOutput}, {}}}
			manager, err := NewManager(runner, "/usr/sbin/ip", "/usr/sbin/nft")
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.Apply(context.Background(), "vpnpool-1234567890", validWorkerRules()); err != nil {
				t.Fatalf("Apply() error = %v", err)
			}
			if len(runner.stdin) != 2 {
				t.Fatalf("commands = %#v", runner.args)
			}
			hasDelete := strings.Contains(runner.stdin[1], "delete table inet vpnpoold\n")
			if hasDelete != test.wantDelete {
				t.Fatalf("batch delete = %t, want %t:\n%s", hasDelete, test.wantDelete, runner.stdin[1])
			}
		})
	}
}

type hostCleanupRunner struct {
	results []process.Result
	errors  []error
	args    [][]string
	stdin   []string
}

func (r *hostCleanupRunner) Run(_ context.Context, command process.Command) (process.Result, error) {
	r.args = append(r.args, append([]string(nil), command.Args...))
	r.stdin = append(r.stdin, string(command.Stdin))
	index := len(r.args) - 1
	var result process.Result
	var err error
	if index < len(r.results) {
		result = r.results[index]
	}
	if index < len(r.errors) {
		err = r.errors[index]
	}
	return result, err
}

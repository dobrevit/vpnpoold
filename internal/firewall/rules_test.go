package firewall

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/dobrevit/vpnpoold/internal/process"
)

func TestWorkerRulesFailClosedByMode(t *testing.T) {
	tests := []struct {
		name       string
		mode       Mode
		wantTunnel bool
		wantProxy  bool
	}{
		{name: "bootstrap", mode: ModeBootstrap},
		{name: "active", mode: ModeActive, wantTunnel: true, wantProxy: true},
		{name: "strict", mode: ModeStrict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rules := validRules()
			rules.Mode = test.mode
			text, err := rules.Commands(false)
			if err != nil {
				t.Fatalf("Commands() error = %v", err)
			}
			if !strings.Contains(text, "policy drop") {
				t.Fatalf("rules lack default-drop policy:\n%s", text)
			}
			if strings.Contains(text, "ct state established,related accept") &&
				strings.Contains(text, "output ct state") {
				t.Fatalf("rules contain unscoped established output allowance:\n%s", text)
			}
			hasTunnel := strings.Contains(text, `oifname "tun0" accept`)
			hasProxy := strings.Contains(text, "tcp dport 1081")
			if hasTunnel != test.wantTunnel || hasProxy != test.wantProxy {
				t.Fatalf("mode %s: tunnel=%t proxy=%t\n%s", test.mode, hasTunnel, hasProxy, text)
			}
			if !strings.Contains(text, "198.51.100.10 udp dport 1194") {
				t.Fatalf("OpenVPN endpoint missing:\n%s", text)
			}
		})
	}
}

func TestWorkerRulesRejectsInjection(t *testing.T) {
	rules := validRules()
	rules.VethInterface = `vpn0" accept; #`
	if _, err := rules.Commands(false); err == nil {
		t.Fatal("Commands() unexpectedly accepted an injected interface")
	}
}

func TestManagerAppliesRulesThroughIPNetnsExec(t *testing.T) {
	runner := &firewallRunner{listError: errors.New("table absent")}
	manager, err := NewManager(runner, "/usr/sbin/ip", "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(context.Background(), "vpnpool-1234567890", validRules()); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("commands = %#v", runner.commands)
	}
	apply := runner.commands[1]
	if strings.Join(apply.Args, " ") != "netns exec vpnpool-1234567890 /usr/sbin/nft -f -" {
		t.Fatalf("apply args = %#v", apply.Args)
	}
	if !strings.HasPrefix(string(apply.Stdin), "add table inet vpnpoold\n") {
		t.Fatalf("apply input = %q", apply.Stdin)
	}
}

func validRules() WorkerRules {
	return WorkerRules{
		Mode:            ModeActive,
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

type firewallRunner struct {
	commands  []process.Command
	listError error
}

func (r *firewallRunner) Run(_ context.Context, command process.Command) (process.Result, error) {
	r.commands = append(r.commands, command)
	if len(command.Args) >= 5 && command.Args[len(command.Args)-5] == "list" {
		return process.Result{}, r.listError
	}
	if strings.Contains(strings.Join(command.Args, " "), " list table ") {
		return process.Result{}, r.listError
	}
	return process.Result{}, nil
}

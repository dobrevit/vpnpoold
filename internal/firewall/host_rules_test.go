package firewall

import (
	"net/netip"
	"strings"
	"testing"
)

func TestHostRulesAreNarrowlyScoped(t *testing.T) {
	rules := HostRules{
		WorkerSubnet:    netip.MustParsePrefix("10.231.0.0/16"),
		UplinkInterface: "eth0",
		WorkerVeths:     []string{"vphbbbbbbbbbb", "vphaaaaaaaaaa"},
		OpenVPNEndpoints: []netip.Addr{
			netip.MustParseAddr("203.0.113.20"),
			netip.MustParseAddr("198.51.100.10"),
		},
	}
	text, err := rules.Commands(false)
	if err != nil {
		t.Fatalf("Commands() error = %v", err)
	}
	for _, expected := range []string{
		"policy accept",
		`iifname { "vphaaaaaaaaaa", "vphbbbbbbbbbb" } meta nfproto ipv6 drop`,
		`iifname { "vphaaaaaaaaaa", "vphbbbbbbbbbb" } ip saddr != 10.231.0.0/16 drop`,
		`ip daddr != { 198.51.100.10, 203.0.113.20 } drop`,
		`oifname != "eth0" drop`,
		`ip saddr 10.231.0.0/16 ip daddr { 198.51.100.10, 203.0.113.20 } oifname "eth0" masquerade`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("rules missing %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "policy drop") {
		t.Fatalf("host rules would alter unrelated forwarding policy:\n%s", text)
	}
}

func TestHostRulesRejectInjectionAndIPv6Endpoint(t *testing.T) {
	base := HostRules{
		WorkerSubnet:     netip.MustParsePrefix("10.231.0.0/16"),
		UplinkInterface:  "eth0",
		WorkerVeths:      []string{"vphaaaaaaaaaa"},
		OpenVPNEndpoints: []netip.Addr{netip.MustParseAddr("198.51.100.10")},
	}
	injected := base
	injected.UplinkInterface = `eth0" accept`
	if _, err := injected.Commands(false); err == nil {
		t.Fatal("injected interface unexpectedly accepted")
	}
	ipv6 := base
	ipv6.OpenVPNEndpoints = []netip.Addr{netip.MustParseAddr("2001:db8::1")}
	if _, err := ipv6.Commands(false); err == nil {
		t.Fatal("IPv6 bootstrap endpoint unexpectedly accepted")
	}
}

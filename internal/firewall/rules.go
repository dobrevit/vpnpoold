package firewall

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/dobrevit/vpnpoold/internal/netutil"
)

type Mode uint8

const (
	ModeBootstrap Mode = iota
	ModeActive
	ModeStrict
)

func (m Mode) String() string {
	switch m {
	case ModeBootstrap:
		return "bootstrap"
	case ModeActive:
		return "active"
	case ModeStrict:
		return "strict"
	default:
		return fmt.Sprintf("unknown-%d", m)
	}
}

type Endpoint struct {
	Address  netip.Addr
	Protocol string
	Port     uint16
}

type WorkerRules struct {
	Mode             Mode
	VethInterface    string
	TunnelInterface  string
	HostAddress      netip.Addr
	ProxyPort        uint16
	OpenVPNEndpoints []Endpoint
}

func (r WorkerRules) Validate() error {
	if r.Mode != ModeBootstrap && r.Mode != ModeActive && r.Mode != ModeStrict {
		return errors.New("firewall mode is invalid")
	}
	if !netutil.IsValidInterfaceName(r.VethInterface) {
		return errors.New("veth interface name is invalid")
	}
	if !netutil.IsValidInterfaceName(r.TunnelInterface) {
		return errors.New("tunnel interface name is invalid")
	}
	if !r.HostAddress.IsValid() || !r.HostAddress.Is4() {
		return errors.New("host address must be IPv4")
	}
	if r.Mode == ModeActive && r.ProxyPort == 0 {
		return errors.New("active firewall mode requires a proxy port")
	}
	if len(r.OpenVPNEndpoints) == 0 {
		return errors.New("at least one resolved OpenVPN endpoint is required")
	}
	for index, endpoint := range r.OpenVPNEndpoints {
		if !endpoint.Address.IsValid() || endpoint.Address.IsUnspecified() ||
			endpoint.Address.IsMulticast() {
			return fmt.Errorf("OpenVPN endpoint %d address is invalid", index)
		}
		if endpoint.Protocol != "tcp" && endpoint.Protocol != "udp" {
			return fmt.Errorf("OpenVPN endpoint %d protocol must be tcp or udp", index)
		}
		if endpoint.Port == 0 {
			return fmt.Errorf("OpenVPN endpoint %d port is required", index)
		}
	}
	return nil
}

// Commands returns an nftables transaction body. All caller-controlled
// identifiers are validated before interpolation. Rules use default-drop
// policies and interface-scoped connection tracking so strict mode cannot keep
// established data sessions alive through the tunnel.
func (r WorkerRules) Commands(tableExists bool) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}

	var lines []string
	if tableExists {
		// Delete and recreate in one nft batch. nft applies the batch as a
		// transaction, so there is no permissive interval between rule sets.
		lines = append(lines, "delete table inet vpnpoold")
	}
	lines = append(lines, "add table inet vpnpoold")
	lines = append(lines,
		"add chain inet vpnpoold input { type filter hook input priority -100; policy drop; }",
		"add chain inet vpnpoold output { type filter hook output priority -100; policy drop; }",
		"add chain inet vpnpoold forward { type filter hook forward priority -100; policy drop; }",
		`add rule inet vpnpoold input iifname "lo" accept`,
		`add rule inet vpnpoold output oifname "lo" accept`,
		fmt.Sprintf(`add rule inet vpnpoold input iifname "%s" ct state established,related accept`, r.VethInterface),
		fmt.Sprintf(`add rule inet vpnpoold output oifname "%s" ct state established,related accept`, r.VethInterface),
	)

	endpoints := append([]Endpoint(nil), r.OpenVPNEndpoints...)
	sort.Slice(endpoints, func(i, j int) bool {
		left := endpoints[i].Address.String() + endpoints[i].Protocol + fmt.Sprint(endpoints[i].Port)
		right := endpoints[j].Address.String() + endpoints[j].Protocol + fmt.Sprint(endpoints[j].Port)
		return left < right
	})
	for _, endpoint := range endpoints {
		family := "ip"
		if endpoint.Address.Is6() {
			family = "ip6"
		}
		lines = append(lines, fmt.Sprintf(
			`add rule inet vpnpoold output oifname "%s" %s daddr %s %s dport %d accept`,
			r.VethInterface,
			family,
			endpoint.Address,
			endpoint.Protocol,
			endpoint.Port,
		))
	}

	if r.Mode == ModeActive {
		lines = append(lines,
			fmt.Sprintf(`add rule inet vpnpoold input iifname "%s" ct state established,related accept`, r.TunnelInterface),
			fmt.Sprintf(`add rule inet vpnpoold output oifname "%s" accept`, r.TunnelInterface),
			fmt.Sprintf(
				`add rule inet vpnpoold input iifname "%s" ip saddr %s tcp dport %d ct state new accept`,
				r.VethInterface,
				r.HostAddress,
				r.ProxyPort,
			),
		)
	}
	return strings.Join(lines, "\n") + "\n", nil
}

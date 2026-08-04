package firewall

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

type HostRules struct {
	WorkerSubnet     netip.Prefix
	UplinkInterface  string
	WorkerVeths      []string
	OpenVPNEndpoints []netip.Addr
}

func (r HostRules) Validate() error {
	if !r.WorkerSubnet.IsValid() || !r.WorkerSubnet.Addr().Is4() ||
		r.WorkerSubnet != r.WorkerSubnet.Masked() {
		return errors.New("worker subnet must be a canonical IPv4 prefix")
	}
	if !interfaceNamePattern.MatchString(r.UplinkInterface) {
		return errors.New("uplink interface name is invalid")
	}
	if len(r.WorkerVeths) == 0 {
		return errors.New("at least one worker veth is required")
	}
	seenVeths := make(map[string]struct{}, len(r.WorkerVeths))
	for _, name := range r.WorkerVeths {
		if !interfaceNamePattern.MatchString(name) {
			return fmt.Errorf("worker veth name %q is invalid", name)
		}
		if _, exists := seenVeths[name]; exists {
			return fmt.Errorf("worker veth name %q is duplicated", name)
		}
		seenVeths[name] = struct{}{}
	}
	if len(r.OpenVPNEndpoints) == 0 {
		return errors.New("at least one resolved IPv4 OpenVPN endpoint is required")
	}
	seenEndpoints := make(map[netip.Addr]struct{}, len(r.OpenVPNEndpoints))
	for _, endpoint := range r.OpenVPNEndpoints {
		if !endpoint.IsValid() || !endpoint.Is4() || endpoint.IsUnspecified() ||
			endpoint.IsMulticast() {
			return fmt.Errorf("OpenVPN endpoint %q must be a usable IPv4 address", endpoint)
		}
		if _, exists := seenEndpoints[endpoint]; exists {
			return fmt.Errorf("OpenVPN endpoint %q is duplicated", endpoint)
		}
		seenEndpoints[endpoint] = struct{}{}
	}
	return nil
}

// Commands creates host bootstrap filtering and NAT without changing the
// default policy for unrelated host forwarding. Traffic arriving from a
// vpnpool veth is dropped unless its source, destination, and uplink all match
// the configured bootstrap path.
func (r HostRules) Commands(tableExists bool) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	veths := append([]string(nil), r.WorkerVeths...)
	sort.Strings(veths)
	endpoints := append([]netip.Addr(nil), r.OpenVPNEndpoints...)
	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].Compare(endpoints[j]) < 0
	})

	var lines []string
	if tableExists {
		lines = append(lines, "delete table inet vpnpoold_host")
	}
	lines = append(lines,
		"add table inet vpnpoold_host",
		"add chain inet vpnpoold_host forward { type filter hook forward priority -100; policy accept; }",
		"add chain inet vpnpoold_host postrouting { type nat hook postrouting priority srcnat; policy accept; }",
	)
	vethSet := nftStringSet(veths)
	endpointSet := nftAddressSet(endpoints)
	lines = append(lines,
		fmt.Sprintf("add rule inet vpnpoold_host forward iifname %s meta nfproto ipv6 drop", vethSet),
		fmt.Sprintf("add rule inet vpnpoold_host forward iifname %s ip saddr != %s drop", vethSet, r.WorkerSubnet),
		fmt.Sprintf("add rule inet vpnpoold_host forward iifname %s ip daddr != %s drop", vethSet, endpointSet),
		fmt.Sprintf(`add rule inet vpnpoold_host forward iifname %s oifname != "%s" drop`, vethSet, r.UplinkInterface),
		fmt.Sprintf(`add rule inet vpnpoold_host postrouting ip saddr %s ip daddr %s oifname "%s" masquerade`, r.WorkerSubnet, endpointSet, r.UplinkInterface),
	)
	return strings.Join(lines, "\n") + "\n", nil
}

func nftStringSet(values []string) string {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = `"` + value + `"`
	}
	return "{ " + strings.Join(quoted, ", ") + " }"
}

func nftAddressSet(values []netip.Addr) string {
	rendered := make([]string, len(values))
	for index, value := range values {
		rendered[index] = value.String()
	}
	return "{ " + strings.Join(rendered, ", ") + " }"
}

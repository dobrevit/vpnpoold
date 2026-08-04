package netutil

import (
	"strings"
	"testing"
)

func TestIdentifierValidators(t *testing.T) {
	tests := []struct {
		name     string
		valid    func(string) bool
		accepted []string
		rejected []string
	}{
		{
			name: "namespace", valid: IsValidNamespaceName,
			accepted: []string{"vpnpool-a", "a", strings.Repeat("a", 63)},
			rejected: []string{"", "VPNPool", "a_b", strings.Repeat("a", 64)},
		},
		{
			name: "interface", valid: IsValidInterfaceName,
			accepted: []string{"tun0", "veth.1", strings.Repeat("a", 15)},
			rejected: []string{"", "bad/interface", strings.Repeat("a", 16)},
		},
		{
			name: "worker ID", valid: IsValidWorkerID,
			accepted: []string{"a", "worker-1", strings.Repeat("a", 32)},
			rejected: []string{"", "Worker", "-worker", "worker-", strings.Repeat("a", 33)},
		},
		{
			name: "resource prefix", valid: IsValidResourcePrefix,
			accepted: []string{"a", "vpnpool", strings.Repeat("a", 31)},
			rejected: []string{"", "1pool", "VPNPool", strings.Repeat("a", 32)},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, value := range test.accepted {
				if !test.valid(value) {
					t.Errorf("rejected valid identifier %q", value)
				}
			}
			for _, value := range test.rejected {
				if test.valid(value) {
					t.Errorf("accepted invalid identifier %q", value)
				}
			}
		})
	}
}

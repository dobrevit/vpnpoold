package netutil

import (
	"net/netip"
	"testing"
)

func TestAllocator(t *testing.T) {
	allocator, err := NewAllocator(netip.MustParsePrefix("10.231.0.0/16"), 30)
	if err != nil {
		t.Fatal(err)
	}
	if allocator.Capacity() != 16384 {
		t.Fatalf("Capacity() = %d", allocator.Capacity())
	}

	first, err := allocator.Allocate(0, "france-1", "vpnpool")
	if err != nil {
		t.Fatal(err)
	}
	if first.Subnet.String() != "10.231.0.0/30" ||
		first.HostAddress.String() != "10.231.0.1/30" ||
		first.NamespaceAddress.String() != "10.231.0.2/30" {
		t.Fatalf("first allocation = %+v", first)
	}
	if len(first.HostVeth) > 15 || len(first.NamespaceVeth) > 15 {
		t.Fatalf("interface names exceed Linux limit: %+v", first)
	}

	second, err := allocator.Allocate(1, "germany-1", "vpnpool")
	if err != nil {
		t.Fatal(err)
	}
	if second.Subnet.String() != "10.231.0.4/30" {
		t.Fatalf("second subnet = %s", second.Subnet)
	}
	if first.Namespace == second.Namespace || first.HostVeth == second.HostVeth {
		t.Fatalf("resource collision: first=%+v second=%+v", first, second)
	}

	repeated, err := allocator.Allocate(0, "france-1", "vpnpool")
	if err != nil {
		t.Fatal(err)
	}
	if repeated != first {
		t.Fatalf("allocation is not deterministic: first=%+v repeated=%+v", first, repeated)
	}
}

func TestAllocatorRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name       string
		parent     string
		workerBits int
	}{
		{name: "IPv6", parent: "fd00::/64", workerBits: 126},
		{name: "child too small", parent: "10.0.0.0/16", workerBits: 15},
		{name: "not enough hosts", parent: "10.0.0.0/16", workerBits: 31},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewAllocator(netip.MustParsePrefix(test.parent), test.workerBits); err == nil {
				t.Fatal("NewAllocator() unexpectedly succeeded")
			}
		})
	}

	allocator, err := NewAllocator(netip.MustParsePrefix("10.0.0.0/30"), 30)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := allocator.Allocate(1, "worker", "vpnpool"); err == nil {
		t.Fatal("out-of-capacity allocation unexpectedly succeeded")
	}
}

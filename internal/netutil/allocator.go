package netutil

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

type Allocation struct {
	Index            int
	WorkerID         string
	Namespace        string
	HostVeth         string
	NamespaceVeth    string
	Subnet           netip.Prefix
	HostAddress      netip.Prefix
	NamespaceAddress netip.Prefix
}

type Allocator struct {
	parent     netip.Prefix
	workerBits int
	subnetSize uint64
	capacity   uint64
}

func NewAllocator(parent netip.Prefix, workerPrefixLength int) (*Allocator, error) {
	parent = parent.Masked()
	if !parent.IsValid() || !parent.Addr().Is4() {
		return nil, errors.New("parent network must be a valid IPv4 prefix")
	}
	if workerPrefixLength < parent.Bits() || workerPrefixLength > 30 {
		return nil, fmt.Errorf("worker prefix length must be between %d and 30", parent.Bits())
	}
	return &Allocator{
		parent:     parent,
		workerBits: workerPrefixLength,
		subnetSize: uint64(1) << (32 - workerPrefixLength),
		capacity:   uint64(1) << (workerPrefixLength - parent.Bits()),
	}, nil
}

func (a *Allocator) Capacity() uint64 {
	return a.capacity
}

func (a *Allocator) Allocate(index int, workerID, namespacePrefix string) (Allocation, error) {
	if index < 0 || uint64(index) >= a.capacity {
		return Allocation{}, fmt.Errorf("worker index %d is outside allocator capacity %d", index, a.capacity)
	}
	if !IsValidResourcePrefix(namespacePrefix) {
		return Allocation{}, errors.New("namespace prefix is invalid")
	}
	if !IsValidWorkerID(workerID) {
		return Allocation{}, errors.New("worker ID is invalid")
	}

	baseBytes := a.parent.Addr().As4()
	base := uint64(binary.BigEndian.Uint32(baseBytes[:]))
	subnetBase := base + uint64(index)*a.subnetSize
	if subnetBase+2 > uint64(^uint32(0)) {
		return Allocation{}, errors.New("allocated subnet exceeds IPv4 address space")
	}

	subnetIP := uint32ToAddr(uint32(subnetBase))
	hostIP := uint32ToAddr(uint32(subnetBase + 1))
	namespaceIP := uint32ToAddr(uint32(subnetBase + 2))
	suffix := resourceSuffix(workerID)

	return Allocation{
		Index:            index,
		WorkerID:         workerID,
		Namespace:        namespacePrefix + "-" + suffix,
		HostVeth:         "vph" + suffix,
		NamespaceVeth:    "vpn" + suffix,
		Subnet:           netip.PrefixFrom(subnetIP, a.workerBits),
		HostAddress:      netip.PrefixFrom(hostIP, a.workerBits),
		NamespaceAddress: netip.PrefixFrom(namespaceIP, a.workerBits),
	}, nil
}

func resourceSuffix(workerID string) string {
	sum := sha256.Sum256([]byte(workerID))
	return fmt.Sprintf("%x", sum[:5])
}

func uint32ToAddr(value uint32) netip.Addr {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return netip.AddrFrom4(raw)
}

package namespace

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/dobrevit/vpnpoold/internal/netutil"
	"github.com/dobrevit/vpnpoold/internal/process"
)

type Manager struct {
	runner     process.Runner
	ipPath     string
	resolver   ResolverStore
	dnsServers []netip.Addr
}

func NewManager(runner process.Runner, ipPath string) (*Manager, error) {
	return newManager(runner, ipPath, nil, nil)
}

func NewManagerWithDNS(
	runner process.Runner,
	ipPath string,
	dnsServers []netip.Addr,
) (*Manager, error) {
	resolver, err := NewOSResolverStore("/etc/netns")
	if err != nil {
		return nil, err
	}
	return newManager(runner, ipPath, resolver, dnsServers)
}

func newManager(
	runner process.Runner,
	ipPath string,
	resolver ResolverStore,
	dnsServers []netip.Addr,
) (*Manager, error) {
	if runner == nil {
		return nil, errors.New("process runner is required")
	}
	if !filepath.IsAbs(ipPath) {
		return nil, errors.New("ip binary path must be absolute")
	}
	if len(dnsServers) > 0 && resolver == nil {
		return nil, errors.New("resolver store is required when DNS servers are configured")
	}
	for index, server := range dnsServers {
		if !usableDNSServer(server) {
			return nil, fmt.Errorf("DNS server %d is invalid", index)
		}
	}
	return &Manager{
		runner: runner, ipPath: ipPath, resolver: resolver,
		dnsServers: append([]netip.Addr(nil), dnsServers...),
	}, nil
}

// Create builds a namespace and veth pair but intentionally does not start any
// workload. The caller must install the namespace firewall before starting
// OpenVPN or a proxy.
func (m *Manager) Create(ctx context.Context, allocation netutil.Allocation) (err error) {
	if err := validateAllocation(allocation); err != nil {
		return err
	}
	exists, err := m.namespaceExists(ctx, allocation.Namespace)
	if err != nil {
		return fmt.Errorf("check namespace %q: %w", allocation.Namespace, err)
	}
	if exists {
		return fmt.Errorf("namespace %q already exists; stale resources must be cleaned before creation", allocation.Namespace)
	}

	created := false
	defer func() {
		if err != nil && created {
			cleanupErr := m.Delete(context.WithoutCancel(ctx), allocation)
			if cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("rollback namespace %q: %w", allocation.Namespace, cleanupErr))
			}
		}
	}()

	steps := []struct {
		operation string
		args      []string
	}{
		{"create network namespace", []string{"netns", "add", allocation.Namespace}},
		{"create veth pair", []string{"link", "add", allocation.HostVeth, "type", "veth", "peer", "name", allocation.NamespaceVeth}},
		{"move peer veth into namespace", []string{"link", "set", allocation.NamespaceVeth, "netns", allocation.Namespace}},
		{"assign host veth address", []string{"addr", "add", allocation.HostAddress.String(), "dev", allocation.HostVeth}},
		{"bring host veth up", []string{"link", "set", "dev", allocation.HostVeth, "up"}},
		{"bring namespace loopback up", []string{"-n", allocation.Namespace, "link", "set", "dev", "lo", "up"}},
		{"assign namespace veth address", []string{"-n", allocation.Namespace, "addr", "add", allocation.NamespaceAddress.String(), "dev", allocation.NamespaceVeth}},
		{"bring namespace veth up", []string{"-n", allocation.Namespace, "link", "set", "dev", allocation.NamespaceVeth, "up"}},
		{"add namespace bootstrap route", []string{"-n", allocation.Namespace, "route", "add", "default", "via", allocation.HostAddress.Addr().String(), "dev", allocation.NamespaceVeth}},
	}
	for index, step := range steps {
		if _, runErr := m.runner.Run(ctx, process.Command{Path: m.ipPath, Args: step.args}); runErr != nil {
			return fmt.Errorf("%s for worker %q: %w", step.operation, allocation.WorkerID, runErr)
		}
		if index == 0 {
			created = true
			if len(m.dnsServers) > 0 {
				if configureErr := m.resolver.Configure(
					allocation.Namespace,
					m.dnsServers,
				); configureErr != nil {
					return fmt.Errorf(
						"configure namespace DNS for worker %q: %w",
						allocation.WorkerID,
						configureErr,
					)
				}
			}
		}
	}
	return nil
}

// Delete is idempotent. It lists exact resource names first so "not found" is
// distinguished from command failures such as insufficient privileges.
func (m *Manager) Delete(ctx context.Context, allocation netutil.Allocation) error {
	if err := validateAllocation(allocation); err != nil {
		return err
	}
	var problems []error
	exists, err := m.namespaceExists(ctx, allocation.Namespace)
	if err != nil {
		problems = append(problems, fmt.Errorf("list namespaces: %w", err))
	} else if exists {
		if _, err := m.runner.Run(ctx, process.Command{
			Path: m.ipPath,
			Args: []string{"netns", "delete", allocation.Namespace},
		}); err != nil {
			problems = append(problems, fmt.Errorf("delete namespace %q: %w", allocation.Namespace, err))
		}
	}

	linkExists, err := m.linkExists(ctx, allocation.HostVeth)
	if err != nil {
		problems = append(problems, fmt.Errorf("list host links: %w", err))
	} else if linkExists {
		if _, deleteErr := m.runner.Run(ctx, process.Command{
			Path: m.ipPath,
			Args: []string{"link", "delete", allocation.HostVeth},
		}); deleteErr != nil {
			stillExists, checkErr := m.linkExists(ctx, allocation.HostVeth)
			if checkErr != nil {
				problems = append(problems, errors.Join(
					fmt.Errorf("delete host veth %q: %w", allocation.HostVeth, deleteErr),
					fmt.Errorf("recheck host veth %q: %w", allocation.HostVeth, checkErr),
				))
			} else if stillExists {
				problems = append(problems, fmt.Errorf(
					"delete host veth %q: %w",
					allocation.HostVeth,
					deleteErr,
				))
			}
		}
	}
	if m.resolver != nil {
		if err := m.resolver.Delete(allocation.Namespace); err != nil {
			problems = append(problems, fmt.Errorf("delete namespace resolver configuration: %w", err))
		}
	}
	return errors.Join(problems...)
}

func (m *Manager) namespaceExists(ctx context.Context, name string) (bool, error) {
	result, err := m.runner.Run(ctx, process.Command{Path: m.ipPath, Args: []string{"netns", "list"}})
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(result.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 0 && fields[0] == name {
			return true, nil
		}
	}
	return false, nil
}

func (m *Manager) linkExists(ctx context.Context, name string) (bool, error) {
	result, err := m.runner.Run(ctx, process.Command{Path: m.ipPath, Args: []string{"-o", "link", "show"}})
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(result.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		linkName := strings.TrimSuffix(fields[1], ":")
		linkName = strings.SplitN(linkName, "@", 2)[0]
		if linkName == name {
			return true, nil
		}
	}
	return false, nil
}

func validateAllocation(allocation netutil.Allocation) error {
	if !netutil.IsValidWorkerID(allocation.WorkerID) {
		return errors.New("worker ID is invalid")
	}
	if !netutil.IsValidNamespaceName(allocation.Namespace) {
		return errors.New("namespace name is invalid")
	}
	if !netutil.IsValidInterfaceName(allocation.HostVeth) || !netutil.IsValidInterfaceName(allocation.NamespaceVeth) {
		return errors.New("veth interface name is invalid")
	}
	if !validWorkerAddress(allocation.Subnet, allocation.HostAddress) ||
		!validWorkerAddress(allocation.Subnet, allocation.NamespaceAddress) ||
		allocation.HostAddress.Addr() == allocation.NamespaceAddress.Addr() {
		return errors.New("worker addresses must be distinct IPv4 addresses inside the allocated subnet")
	}
	return nil
}

func validWorkerAddress(subnet, address netip.Prefix) bool {
	return subnet.IsValid() &&
		subnet.Addr().Is4() &&
		address.IsValid() &&
		address.Addr().Is4() &&
		address.Bits() == subnet.Bits() &&
		subnet.Contains(address.Addr())
}

func usableDNSServer(address netip.Addr) bool {
	address = address.Unmap()
	return address.IsValid() &&
		address.Is4() &&
		address.IsGlobalUnicast() &&
		!address.IsLoopback() &&
		!address.IsLinkLocalUnicast() &&
		!address.IsMulticast() &&
		!address.IsUnspecified()
}

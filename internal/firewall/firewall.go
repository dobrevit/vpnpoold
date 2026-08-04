package firewall

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/dobrevit/vpnpoold/internal/netutil"
	"github.com/dobrevit/vpnpoold/internal/process"
)

type Manager struct {
	runner  process.Runner
	ipPath  string
	nftPath string
}

func NewManager(runner process.Runner, ipPath, nftPath string) (*Manager, error) {
	if runner == nil {
		return nil, errors.New("process runner is required")
	}
	if !filepath.IsAbs(ipPath) || !filepath.IsAbs(nftPath) {
		return nil, errors.New("ip and nft binary paths must be absolute")
	}
	return &Manager{runner: runner, ipPath: ipPath, nftPath: nftPath}, nil
}

func (m *Manager) Apply(ctx context.Context, namespace string, rules WorkerRules) error {
	if !netutil.IsValidNamespaceName(namespace) {
		return errors.New("namespace name is invalid")
	}
	result, err := m.runner.Run(ctx, process.Command{
		Path: m.ipPath,
		Args: []string{"netns", "exec", namespace, m.nftPath, "list", "tables"},
	})
	if err != nil {
		return fmt.Errorf("inspect firewall table in namespace %q: %w", namespace, err)
	}
	tableExists := listedTable(result.Stdout, "inet", "vpnpoold")

	commands, err := rules.Commands(tableExists)
	if err != nil {
		return fmt.Errorf("generate %s firewall rules: %w", rules.Mode, err)
	}
	if _, err := m.runner.Run(ctx, process.Command{
		Path:  m.ipPath,
		Args:  []string{"netns", "exec", namespace, m.nftPath, "-f", "-"},
		Stdin: []byte(commands),
	}); err != nil {
		return fmt.Errorf("apply %s firewall rules in namespace %q: %w", rules.Mode, namespace, err)
	}
	return nil
}

func (m *Manager) ApplyHost(ctx context.Context, rules HostRules) error {
	result, err := m.runner.Run(ctx, process.Command{
		Path: m.nftPath,
		Args: []string{"list", "tables"},
	})
	if err != nil {
		return fmt.Errorf("inspect host bootstrap firewall table: %w", err)
	}
	tableExists := listedTable(result.Stdout, "inet", "vpnpoold_host")
	commands, err := rules.Commands(tableExists)
	if err != nil {
		return fmt.Errorf("generate host bootstrap firewall rules: %w", err)
	}
	if _, err := m.runner.Run(ctx, process.Command{
		Path:  m.nftPath,
		Args:  []string{"-f", "-"},
		Stdin: []byte(commands),
	}); err != nil {
		return fmt.Errorf("apply host bootstrap firewall rules: %w", err)
	}
	return nil
}

// RemoveHost removes only vpnpoold's dedicated host table. Listing first
// keeps cleanup idempotent while still surfacing nft permission and runtime
// failures.
func (m *Manager) RemoveHost(ctx context.Context) error {
	result, err := m.runner.Run(ctx, process.Command{
		Path: m.nftPath,
		Args: []string{"list", "tables"},
	})
	if err != nil {
		return fmt.Errorf("inspect host bootstrap firewall table: %w", err)
	}
	if !listedTable(result.Stdout, "inet", "vpnpoold_host") {
		return nil
	}
	if _, err := m.runner.Run(ctx, process.Command{
		Path: m.nftPath,
		Args: []string{"delete", "table", "inet", "vpnpoold_host"},
	}); err != nil {
		return fmt.Errorf("remove host bootstrap firewall table: %w", err)
	}
	return nil
}

func listedTable(output, family, name string) bool {
	wanted := "table " + family + " " + name
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == wanted {
			return true
		}
	}
	return false
}

package namespace

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/dobrevit/vpnpoold/internal/netutil"
)

type ResolverStore interface {
	Configure(string, []netip.Addr) error
	Delete(string) error
}

type OSResolverStore struct {
	root string
}

func NewOSResolverStore(root string) (*OSResolverStore, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("resolver configuration root must be absolute")
	}
	return &OSResolverStore{root: filepath.Clean(root)}, nil
}

func (s *OSResolverStore) Configure(namespace string, servers []netip.Addr) (err error) {
	if s == nil || !netutil.IsValidNamespaceName(namespace) {
		return errors.New("resolver store or namespace is invalid")
	}
	if len(servers) == 0 {
		return errors.New("at least one DNS server is required")
	}
	for index, server := range servers {
		if !usableDNSServer(server) {
			return fmt.Errorf("DNS server %d is invalid", index)
		}
	}

	directory := filepath.Join(s.root, namespace)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create namespace resolver directory: %w", err)
	}
	temp, err := os.CreateTemp(directory, ".resolv.conf-*")
	if err != nil {
		return fmt.Errorf("create namespace resolver file: %w", err)
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		if err != nil {
			_ = os.Remove(tempPath)
		}
	}()
	if err = temp.Chmod(0o644); err != nil {
		return fmt.Errorf("set namespace resolver permissions: %w", err)
	}
	var content strings.Builder
	for _, server := range servers {
		fmt.Fprintf(&content, "nameserver %s\n", server.Unmap())
	}
	if _, err = temp.WriteString(content.String()); err != nil {
		return fmt.Errorf("write namespace resolver file: %w", err)
	}
	if err = temp.Sync(); err != nil {
		return fmt.Errorf("sync namespace resolver file: %w", err)
	}
	if err = temp.Close(); err != nil {
		return fmt.Errorf("close namespace resolver file: %w", err)
	}
	if err = os.Rename(tempPath, filepath.Join(directory, "resolv.conf")); err != nil {
		return fmt.Errorf("publish namespace resolver file: %w", err)
	}
	return nil
}

func (s *OSResolverStore) Delete(namespace string) error {
	if s == nil || !netutil.IsValidNamespaceName(namespace) {
		return errors.New("resolver store or namespace is invalid")
	}
	directory := filepath.Join(s.root, namespace)
	if err := os.Remove(filepath.Join(directory, "resolv.conf")); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove namespace resolver file: %w", err)
	}
	if err := os.Remove(directory); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove namespace resolver directory: %w", err)
	}
	return nil
}

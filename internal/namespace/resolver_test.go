package namespace

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOSResolverStoreConfiguresAndDeletesNamespaceFile(t *testing.T) {
	store, err := NewOSResolverStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	namespace := "vpnpool-1234567890"
	servers := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("8.8.8.8"),
	}
	if err := store.Configure(namespace, servers); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	path := filepath.Join(store.root, namespace, "resolv.conf")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"; got != want {
		t.Fatalf("resolver content = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("resolver mode = %o, want 644", info.Mode().Perm())
	}
	if err := store.Delete(namespace); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("resolver directory remains: %v", err)
	}
	if err := store.Delete(namespace); err != nil {
		t.Fatalf("idempotent Delete() error = %v", err)
	}
}

func TestOSResolverStorePreservesUnexpectedFiles(t *testing.T) {
	store, err := NewOSResolverStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	namespace := "vpnpool-1234567890"
	if err := store.Configure(namespace, []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
	}); err != nil {
		t.Fatal(err)
	}
	unexpected := filepath.Join(store.root, namespace, "hosts")
	if err := os.WriteFile(unexpected, []byte("preserve\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = store.Delete(namespace)
	if err == nil || !strings.Contains(err.Error(), "resolver directory") {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := os.Stat(unexpected); err != nil {
		t.Fatalf("unexpected file was removed: %v", err)
	}
}

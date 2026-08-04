package openvpn

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestOSProfileReaderRequiresPrivateNonSymlinkFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "worker.ovpn")
	if err := os.WriteFile(path, []byte("client\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	reader := OSProfileReader{}
	if _, err := reader.ReadProfile(path, 1024); err == nil ||
		!strings.Contains(err.Error(), "group or other") {
		t.Fatalf("ReadProfile() permissions error = %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "worker-link.ovpn")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadProfile(link, 1024); err == nil ||
		!strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("ReadProfile() symlink error = %v", err)
	}
}

func TestParseRemotesSkipsInlineSecrets(t *testing.T) {
	profile := `client
proto udp
remote vpn-one.example 1194
<key>
remote should-never-be-parsed.example 443 tcp
-----BEGIN PRIVATE KEY-----
secret material
-----END PRIVATE KEY-----
</key>
remote "vpn-two.example" 443 tcp-client # comment
remote 198.51.100.10
`
	got, err := parseRemotes([]byte(profile))
	if err != nil {
		t.Fatalf("parseRemotes() error = %v", err)
	}
	want := []Remote{
		{Host: "vpn-one.example", Port: 1194, Protocol: "udp"},
		{Host: "vpn-two.example", Port: 443, Protocol: "tcp"},
		{Host: "198.51.100.10", Port: 1194, Protocol: "udp"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("remotes = %#v, want %#v", got, want)
	}
}

func TestParseRemotesErrorsDoNotExposeLineContent(t *testing.T) {
	secret := "top-secret-password"
	_, err := parseRemotes([]byte(`remote "` + secret + "\n"))
	if err == nil {
		t.Fatal("parseRemotes() unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error exposed profile content: %v", err)
	}
}

func TestParseRemotesRejectsPrivilegedSideEffects(t *testing.T) {
	for _, directive := range []string{
		"daemon",
		"config /tmp/extra.conf",
		"cd /tmp",
		"chroot /tmp/jail",
		"up /root/execute-me",
		"plugin /root/execute-me.so",
		"iproute /root/fake-ip",
		"log /root/overwrite-me",
		"script-security 2",
	} {
		t.Run(strings.Fields(directive)[0], func(t *testing.T) {
			_, err := parseRemotes([]byte(
				directive + "\nremote vpn.example 1194\n",
			))
			if err == nil || !strings.Contains(err.Error(), "prohibited") {
				t.Fatalf("parseRemotes() error = %v", err)
			}
		})
	}
}

func TestParseRemotesPreservesConnectionProtocolScope(t *testing.T) {
	profile := `client
proto udp
remote global.example 1194
<connection>
remote tcp.example 443
proto tcp-client
</connection>
remote global-two.example 1195
`
	got, err := parseRemotes([]byte(profile))
	if err != nil {
		t.Fatalf("parseRemotes() error = %v", err)
	}
	want := []Remote{
		{Host: "global.example", Port: 1194, Protocol: "udp"},
		{Host: "tcp.example", Port: 443, Protocol: "tcp"},
		{Host: "global-two.example", Port: 1195, Protocol: "udp"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("remotes = %#v, want %#v", got, want)
	}
}

func TestResolveRemotes(t *testing.T) {
	resolver := fakeResolver{
		"vpn.example": {
			netip.MustParseAddr("203.0.113.5"),
			netip.MustParseAddr("203.0.113.5"),
			netip.MustParseAddr("2001:db8::5"),
		},
	}
	got, err := ResolveRemotes(context.Background(), resolver, []Remote{
		{Host: "vpn.example", Port: 1194, Protocol: "udp"},
		{Host: "198.51.100.10", Port: 443, Protocol: "tcp"},
	})
	if err != nil {
		t.Fatalf("ResolveRemotes() error = %v", err)
	}
	want := []ResolvedEndpoint{
		{Address: netip.MustParseAddr("203.0.113.5"), Port: 1194, Protocol: "udp"},
		{Address: netip.MustParseAddr("2001:db8::5"), Port: 1194, Protocol: "udp"},
		{Address: netip.MustParseAddr("198.51.100.10"), Port: 443, Protocol: "tcp"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("endpoints = %#v, want %#v", got, want)
	}
}

type fakeResolver map[string][]netip.Addr

func (r fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	addresses, exists := r[host]
	if !exists {
		return nil, errors.New("not found")
	}
	return addresses, nil
}

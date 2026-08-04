package openvpn

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteDerivedProfilePreservesSourceAndInlineSecrets(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "source.ovpn")
	original := "client\r\nremote vpn.example 1194 udp\r\n<auth-user-pass>\r\nuser\r\nsecret\r\n</auth-user-pass>\r\nremote 192.0.2.2 443 tcp\r\n"
	if err := os.WriteFile(source, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "derived.ovpn")
	endpoints := []ResolvedEndpoint{
		{Address: netip.MustParseAddr("198.51.100.7"), Port: 1194, Protocol: "udp"},
		{Address: netip.MustParseAddr("203.0.113.8"), Port: 443, Protocol: "tcp"},
	}
	if err := WriteDerivedProfile(OSProfileReader{}, source, destination, endpoints); err != nil {
		t.Fatalf("WriteDerivedProfile() error = %v", err)
	}

	sourceData, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(sourceData) != original {
		t.Fatal("source profile was modified")
	}
	derived, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	text := string(derived)
	for _, expected := range []string{
		"<auth-user-pass>\r\nuser\r\nsecret\r\n</auth-user-pass>",
		"remote 198.51.100.7 1194 udp",
		"remote 203.0.113.8 443 tcp",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("derived profile missing %q", expected)
		}
	}
	if strings.Contains(text, "vpn.example") || strings.Contains(text, "192.0.2.2") {
		t.Fatal("derived profile retained an original remote")
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("derived profile mode = %o, want 600", got)
	}
}

func TestWriteDerivedProfileRejectsConnectionBlocks(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "source.ovpn")
	if err := os.WriteFile(source, []byte("<connection>\nremote vpn.example 1194\n</connection>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := WriteDerivedProfile(OSProfileReader{}, source, filepath.Join(directory, "derived.ovpn"), []ResolvedEndpoint{{
		Address: netip.MustParseAddr("198.51.100.7"), Port: 1194, Protocol: "udp",
	}})
	if err == nil || !strings.Contains(err.Error(), "connection blocks") {
		t.Fatalf("WriteDerivedProfile() error = %v", err)
	}
}

func TestWriteDerivedProfileRequiresPrivateDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "source.ovpn")
	if err := os.WriteFile(source, []byte("remote vpn.example 1194\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := WriteDerivedProfile(OSProfileReader{}, source, filepath.Join(directory, "derived.ovpn"), []ResolvedEndpoint{{
		Address: netip.MustParseAddr("198.51.100.7"), Port: 1194, Protocol: "udp",
	}})
	if err == nil || !strings.Contains(err.Error(), "must not be accessible") {
		t.Fatalf("WriteDerivedProfile() error = %v", err)
	}
}

func TestWriteResolvedProfilePreservesConnectionEndpointMapping(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "source.ovpn")
	profile := "client\nremote udp.example 1194 udp\n<connection>\n  proto tcp-client\n  remote tcp.example 443\n</connection>\n"
	if err := os.WriteFile(source, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "derived.ovpn")
	groups := []ResolvedRemote{
		{
			Source: Remote{Host: "udp.example", Port: 1194, Protocol: "udp"},
			Endpoints: []ResolvedEndpoint{
				{Address: netip.MustParseAddr("198.51.100.10"), Port: 1194, Protocol: "udp"},
			},
		},
		{
			Source: Remote{Host: "tcp.example", Port: 443, Protocol: "tcp"},
			Endpoints: []ResolvedEndpoint{
				{Address: netip.MustParseAddr("203.0.113.20"), Port: 443, Protocol: "tcp"},
				{Address: netip.MustParseAddr("203.0.113.21"), Port: 443, Protocol: "tcp"},
			},
		},
	}
	if err := WriteResolvedProfile(OSProfileReader{}, source, destination, groups); err != nil {
		t.Fatalf("WriteResolvedProfile() error = %v", err)
	}
	derived, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	text := string(derived)
	for _, expected := range []string{
		"remote 198.51.100.10 1194 udp\n<connection>",
		"  remote 203.0.113.20 443 tcp",
		"  remote 203.0.113.21 443 tcp",
		"</connection>",
		"redirect-gateway def1",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("derived profile missing %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "udp.example") || strings.Contains(text, "tcp.example") {
		t.Fatalf("derived profile retained a hostname:\n%s", text)
	}
}

func TestWriteResolvedProfileUsesCredentialsFileWithoutChangingSource(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "source.ovpn")
	original := "client\r\nauth-user-pass\r\nremote vpn.example 1194 udp\r\n"
	if err := os.WriteFile(source, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "derived.ovpn")
	groups := []ResolvedRemote{{
		Source: Remote{Host: "vpn.example", Port: 1194, Protocol: "udp"},
		Endpoints: []ResolvedEndpoint{{
			Address: netip.MustParseAddr("198.51.100.10"),
			Port:    1194, Protocol: "udp",
		}},
	}}
	credentialsFile := "/run/vpnpoold/credentials/test user"
	if err := WriteResolvedProfileWithCredentials(
		OSProfileReader{},
		source,
		destination,
		credentialsFile,
		groups,
	); err != nil {
		t.Fatalf("WriteResolvedProfileWithCredentials() error = %v", err)
	}

	sourceData, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(sourceData) != original {
		t.Fatal("source profile was modified")
	}
	derived, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(
		string(derived),
		`auth-user-pass "/run/vpnpoold/credentials/test user"`,
	) {
		t.Fatal("derived profile does not reference the configured credentials file")
	}
	if strings.Contains(string(derived), "\r\nauth-user-pass\r\n") {
		t.Fatal("derived profile retained the interactive auth-user-pass directive")
	}
}

func TestWriteResolvedProfileRemovesManagementDirectivesFromDerivedCopy(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "source.ovpn")
	original := "client\nmanagement 127.0.0.1 7505\nmanagement-query-passwords\nmanagement-hold\nremote vpn.example 1194 udp\n"
	if err := os.WriteFile(source, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "derived.ovpn")
	if err := WriteResolvedProfile(
		OSProfileReader{},
		source,
		destination,
		[]ResolvedRemote{{
			Source: Remote{Host: "vpn.example", Port: 1194, Protocol: "udp"},
			Endpoints: []ResolvedEndpoint{{
				Address:  netip.MustParseAddr("198.51.100.10"),
				Port:     1194,
				Protocol: "udp",
			}},
		}},
	); err != nil {
		t.Fatalf("WriteResolvedProfile() error = %v", err)
	}
	sourceData, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(sourceData) != original {
		t.Fatal("source profile was modified")
	}
	derived, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(derived)), "management") {
		t.Fatalf("derived profile retained daemon-owned management settings:\n%s", derived)
	}
}

func TestWriteResolvedProfileQueriesUsernamePasswordViaManagement(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "source.ovpn")
	original := "client\nauth-user-pass old-file\naskpass old-key-password\nremote vpn.example 1194 udp\n"
	if err := os.WriteFile(source, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "derived.ovpn")
	err := WriteResolvedProfileWithCredentialOptions(
		OSProfileReader{},
		source,
		destination,
		CredentialOptions{
			File:                         "/run/vpnpoold/credentials/worker",
			QueryViaManagement:           true,
			QueryPrivateKeyViaManagement: true,
		},
		[]ResolvedRemote{{
			Source: Remote{Host: "vpn.example", Port: 1194, Protocol: "udp"},
			Endpoints: []ResolvedEndpoint{{
				Address: netip.MustParseAddr("198.51.100.20"),
				Port:    1194, Protocol: "udp",
			}},
		}},
	)
	if err != nil {
		t.Fatalf("WriteResolvedProfileWithCredentialOptions() error = %v", err)
	}
	derived, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(derived), "\nauth-user-pass\n") {
		t.Fatalf("derived profile does not query management:\n%s", derived)
	}
	if !strings.Contains(string(derived), "\naskpass\n") {
		t.Fatalf("derived profile does not query a private-key password:\n%s", derived)
	}
	if strings.Contains(string(derived), "old-file") ||
		strings.Contains(string(derived), "old-key-password") ||
		strings.Contains(string(derived), "/run/vpnpoold/credentials/worker") {
		t.Fatalf("derived profile exposed a credentials path:\n%s", derived)
	}
	sourceAfter, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(sourceAfter) != original {
		t.Fatal("source profile changed")
	}
}

func TestWriteResolvedProfileRejectsMissingCredentialsDirective(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "source.ovpn")
	if err := os.WriteFile(source, []byte("remote vpn.example 1194\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := WriteResolvedProfileWithCredentials(
		OSProfileReader{},
		source,
		filepath.Join(directory, "derived.ovpn"),
		"/run/vpnpoold/credentials",
		[]ResolvedRemote{{
			Source: Remote{Host: "vpn.example", Port: 1194, Protocol: "udp"},
			Endpoints: []ResolvedEndpoint{{
				Address: netip.MustParseAddr("198.51.100.10"),
				Port:    1194, Protocol: "udp",
			}},
		}},
	)
	if err == nil || !strings.Contains(err.Error(), "no auth-user-pass directive") {
		t.Fatalf("WriteResolvedProfileWithCredentials() error = %v", err)
	}
}

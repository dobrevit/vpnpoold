package health

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/dobrevit/vpnpoold/internal/proxy/socks5"
)

func TestParseObservedIP(t *testing.T) {
	tests := []struct {
		name      string
		format    string
		field     string
		body      string
		want      string
		wantError string
	}{
		{name: "plain IPv4", format: "plain_text", body: "8.8.8.8\n", want: "8.8.8.8"},
		{name: "nested JSON", format: "json", field: "data.ip", body: `{"data":{"ip":"2001:4860:4860::8888"}}`, want: "2001:4860:4860::8888"},
		{name: "empty", format: "plain_text", body: " \n", wantError: "empty"},
		{name: "private", format: "plain_text", body: "10.0.0.1", wantError: "not public"},
		{name: "loopback", format: "plain_text", body: "127.0.0.1", wantError: "not public"},
		{name: "invalid", format: "plain_text", body: "not-an-ip", wantError: "valid IP"},
		{name: "JSON field missing", format: "json", field: "ip", body: `{}`, wantError: "missing"},
		{name: "JSON wrong type", format: "json", field: "ip", body: `{"ip":123}`, wantError: "string"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			address, err := ParseObservedIP(test.format, test.field, []byte(test.body))
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if address.String() != test.want {
				t.Fatalf("address = %s, want %s", address, test.want)
			}
		})
	}
}

func TestRegistryRejectsLeaksMismatchAndDuplicates(t *testing.T) {
	registry := NewRegistry()
	if err := registry.SetHostWANIPs([]netip.Addr{netip.MustParseAddr("4.4.4.4")}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.VerifyAndRecord(
		"worker-host-leak",
		netip.MustParseAddr("4.4.4.4"),
		VerificationPolicy{},
	); err == nil || !strings.Contains(err.Error(), "VPN leak") {
		t.Fatalf("dynamic host leak error = %v", err)
	}
	publicIP := netip.MustParseAddr("8.8.8.8")
	first, err := registry.VerifyAndRecord("worker-1", publicIP, VerificationPolicy{
		ExpectedIP:        publicIP,
		EnforceUniqueness: true,
	})
	if err != nil {
		t.Fatalf("first verification: %v", err)
	}
	if !first.ExpectedIPConfigured || !first.ExpectedIPChecked || !first.ExpectedIPMatches ||
		!first.UniquenessEnforced || !first.UniquenessChecked || !first.PublicIPUnique {
		t.Fatalf("required verification evidence = %+v", first)
	}
	if _, err := registry.VerifyAndRecord("worker-2", publicIP, VerificationPolicy{
		EnforceUniqueness: true,
	}); err == nil || !strings.Contains(err.Error(), "duplicates") {
		t.Fatalf("duplicate verification error = %v", err)
	}
	if _, err := registry.VerifyAndRecord("worker-2", netip.MustParseAddr("1.1.1.1"), VerificationPolicy{
		ExpectedIP: netip.MustParseAddr("9.9.9.9"),
	}); err == nil || !strings.Contains(err.Error(), "expected") {
		t.Fatalf("expected-IP error = %v", err)
	}
	result, err := registry.VerifyAndRecord("worker-1", netip.MustParseAddr("9.9.9.9"), VerificationPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.PreviousIP != publicIP {
		t.Fatalf("change result = %+v", result)
	}
	if result.ExpectedIPConfigured || result.ExpectedIPChecked || result.ExpectedIPMatches ||
		result.UniquenessEnforced || result.UniquenessChecked || result.PublicIPUnique {
		t.Fatalf("optional verification evidence = %+v", result)
	}
}

func TestRegistryRemoveReleasesUniquePublicIP(t *testing.T) {
	registry := NewRegistry()
	address := netip.MustParseAddr("8.8.8.8")
	policy := VerificationPolicy{EnforceUniqueness: true}
	if _, err := registry.VerifyAndRecord("worker-1", address, policy); err != nil {
		t.Fatal(err)
	}
	registry.Remove("worker-1")
	if _, err := registry.VerifyAndRecord("worker-2", address, policy); err != nil {
		t.Fatalf("replacement worker remained blocked: %v", err)
	}
}

func TestCheckerUsesWorkerSOCKSPath(t *testing.T) {
	echo := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "8.8.4.4\n")
	}))
	defer echo.Close()

	proxyListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyServer, err := socks5.NewServer(socks5.Config{
		HandshakeTimeout: time.Second,
		ConnectTimeout:   time.Second,
		IdleTimeout:      time.Second,
	}, &net.Dialer{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- proxyServer.Serve(ctx, proxyListener) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("SOCKS server: %v", err)
		}
	}()

	checker := Checker{
		Client:         NewWorkerHTTPClient(proxyListener.Addr().String(), time.Second, time.Second),
		URL:            echo.URL,
		ResponseFormat: "plain_text",
	}
	address, err := checker.Check(context.Background())
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if address.String() != "8.8.4.4" {
		t.Fatalf("address = %s", address)
	}
	if proxyServer.Stats().ConnectionsTotal != 1 {
		t.Fatalf("SOCKS connections = %d", proxyServer.Stats().ConnectionsTotal)
	}
}

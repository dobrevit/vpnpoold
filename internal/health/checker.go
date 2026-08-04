package health

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/dobrevit/vpnpoold/internal/proxy/socks5"
)

const defaultMaxResponseBytes = 4096

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Checker struct {
	Client           HTTPDoer
	URL              string
	ResponseFormat   string
	JSONField        string
	MaxResponseBytes int64
}

func NewWorkerHTTPClient(proxyAddress string, connectTimeout, handshakeTimeout time.Duration) *http.Client {
	netDialer := &net.Dialer{Timeout: connectTimeout}
	workerDialer := socks5.ClientDialer{
		ProxyAddress:     proxyAddress,
		NetDialer:        netDialer,
		HandshakeTimeout: handshakeTimeout,
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           workerDialer.DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   connectTimeout,
		ResponseHeaderTimeout: connectTimeout,
		DisableKeepAlives:     true,
	}
	return &http.Client{Transport: transport}
}

// NewDirectHTTPClient deliberately ignores HTTP_PROXY and related environment
// variables so startup host-IP discovery observes the daemon host's direct
// route rather than an operator shell proxy.
func NewDirectHTTPClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
	}
	return &http.Client{Transport: transport, Timeout: timeout}
}

func (c Checker) Check(ctx context.Context) (netip.Addr, error) {
	if c.Client == nil {
		return netip.Addr{}, errors.New("health HTTP client is required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("create public-IP request: %w", err)
	}
	request.Header.Set("Accept", "text/plain, application/json")
	response, err := c.Client.Do(request)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("request public IP through worker: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return netip.Addr{}, fmt.Errorf("public-IP endpoint returned HTTP status %d", response.StatusCode)
	}
	limit := c.MaxResponseBytes
	if limit <= 0 {
		limit = defaultMaxResponseBytes
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("read public-IP response: %w", err)
	}
	if int64(len(body)) > limit {
		return netip.Addr{}, fmt.Errorf("public-IP response exceeds %d-byte limit", limit)
	}
	address, err := ParseObservedIP(c.ResponseFormat, c.JSONField, body)
	if err != nil {
		return netip.Addr{}, err
	}
	return address, nil
}

func ValidatePublicIP(address netip.Addr) error {
	if !address.IsValid() {
		return errors.New("observed public IP is invalid")
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() ||
		address.IsPrivate() ||
		address.IsLoopback() ||
		address.IsLinkLocalUnicast() ||
		address.IsMulticast() ||
		address.IsUnspecified() {
		return fmt.Errorf("observed address %s is not public unicast", address)
	}
	return nil
}

func parsePlainText(body []byte) (netip.Addr, error) {
	value := strings.TrimSpace(string(body))
	if value == "" {
		return netip.Addr{}, errors.New("public-IP response is empty")
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, errors.New("public-IP response does not contain a valid IP address")
	}
	address = address.Unmap()
	if err := ValidatePublicIP(address); err != nil {
		return netip.Addr{}, err
	}
	return address, nil
}

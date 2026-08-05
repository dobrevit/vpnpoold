package workerproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/dobrevit/vpnpoold/internal/proxy/socks5"
)

func TestServerRelaysSOCKSAndStopsWithContext(t *testing.T) {
	destination := startEchoServer(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		AllowedClientAddress: netip.MustParseAddr("127.0.0.1"),
		HandshakeTimeout:     time.Second,
		ConnectTimeout:       time.Second,
		IdleTimeout:          time.Second,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()

	dialer := socks5.ClientDialer{
		ProxyAddress: listener.Addr().String(), NetDialer: &net.Dialer{},
		HandshakeTimeout: time.Second,
	}
	connection, err := dialer.DialContext(context.Background(), "tcp", destination)
	if err != nil {
		cancel()
		t.Fatalf("DialContext() error = %v", err)
	}
	payload := []byte("through microproxy")
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != string(payload) {
		t.Fatalf("reply = %q", reply)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not stop")
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := connection.Read(make([]byte, 1)); err == nil {
		t.Fatal("active SOCKS session survived server cancellation")
	}
}

func TestServerEnforcesHandshakeTimeoutWithoutLimitingEstablishedSession(t *testing.T) {
	destination := startEchoServer(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	const handshakeTimeout = 40 * time.Millisecond
	server, err := New(Config{
		AllowedClientAddress: netip.MustParseAddr("127.0.0.1"),
		HandshakeTimeout:     handshakeTimeout,
		ConnectTimeout:       time.Second,
		IdleTimeout:          time.Second,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	slowClient, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * handshakeTimeout)
	_ = slowClient.SetDeadline(time.Now().Add(time.Second))
	if _, err := slowClient.Write([]byte{5, 1, 0}); err == nil {
		if _, err := slowClient.Read(make([]byte, 2)); err == nil {
			t.Fatal("slow SOCKS handshake survived the configured timeout")
		}
	}
	_ = slowClient.Close()

	dialer := socks5.ClientDialer{
		ProxyAddress: listener.Addr().String(), NetDialer: &net.Dialer{},
		HandshakeTimeout: time.Second,
	}
	connection, err := dialer.DialContext(context.Background(), "tcp", destination)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	time.Sleep(2 * handshakeTimeout)
	if _, err := connection.Write([]byte("still alive")); err != nil {
		t.Fatalf("established SOCKS session expired at handshake timeout: %v", err)
	}
	if _, err := io.ReadFull(connection, make([]byte, len("still alive"))); err != nil {
		t.Fatalf("read established SOCKS session: %v", err)
	}
}

func TestServerRoutesSOCKSThroughUpstreamHTTPConnect(t *testing.T) {
	destination := startEchoServer(t)
	proxyAddress, requestedTarget := startHTTPConnectProxy(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		AllowedClientAddress: netip.MustParseAddr("127.0.0.1"),
		UpstreamHTTPProxy:    proxyAddress,
		HandshakeTimeout:     time.Second,
		ConnectTimeout:       time.Second,
		IdleTimeout:          time.Second,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()

	dialer := socks5.ClientDialer{
		ProxyAddress: listener.Addr().String(), NetDialer: &net.Dialer{},
		HandshakeTimeout: time.Second,
	}
	connection, err := dialer.DialContext(context.Background(), "tcp", destination)
	if err != nil {
		cancel()
		t.Fatalf("DialContext() error = %v", err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("via HTTP CONNECT")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(connection, make([]byte, len("via HTTP CONNECT"))); err != nil {
		t.Fatal(err)
	}
	select {
	case target := <-requestedTarget:
		if target != destination {
			t.Fatalf("HTTP CONNECT target = %q, want %q", target, destination)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream HTTP proxy received no CONNECT request")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
}

func TestUpstreamHTTPConnectHandshakeUsesConnectTimeout(t *testing.T) {
	proxyAddress := startHangingHTTPConnectProxy(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		AllowedClientAddress: netip.MustParseAddr("127.0.0.1"),
		UpstreamHTTPProxy:    proxyAddress,
		HandshakeTimeout:     time.Second,
		ConnectTimeout:       25 * time.Millisecond,
		IdleTimeout:          time.Second,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()

	dialer := socks5.ClientDialer{
		ProxyAddress: listener.Addr().String(), NetDialer: &net.Dialer{},
		HandshakeTimeout: time.Second,
	}
	started := time.Now()
	if _, err := dialer.DialContext(context.Background(), "tcp", "example.test:443"); err == nil {
		t.Fatal("DialContext() unexpectedly succeeded through a hanging upstream")
	}
	if elapsed := time.Since(started); elapsed > 300*time.Millisecond {
		t.Fatalf("upstream CONNECT timeout took %v", elapsed)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
}

func TestNewRejectsInvalidUpstreamAndTimeouts(t *testing.T) {
	valid := Config{
		AllowedClientAddress: netip.MustParseAddr("10.231.0.1"),
		HandshakeTimeout:     time.Second, ConnectTimeout: time.Second, IdleTimeout: time.Second,
	}
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "hostname upstream", mutate: func(config *Config) {
			config.UpstreamHTTPProxy = "proxy.example:3128"
		}},
		{name: "loopback upstream", mutate: func(config *Config) {
			config.UpstreamHTTPProxy = "127.0.0.1:3128"
		}},
		{name: "zero timeout", mutate: func(config *Config) {
			config.ConnectTimeout = 0
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if _, err := New(config, nil); err == nil {
				t.Fatal("New() unexpectedly accepted invalid configuration")
			}
		})
	}
}

func TestOutboundDialerRejectsIPv6WhenDisabled(t *testing.T) {
	dialer := outboundDialer{timeout: time.Second}
	if _, err := dialer.DialContext(
		context.Background(), "tcp", "[2001:db8::1]:443",
	); err == nil {
		t.Fatal("DialContext() unexpectedly accepted IPv6")
	}
}

func startEchoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	return listener.Addr().String()
}

func startHTTPConnectProxy(t *testing.T) (string, <-chan string) {
	t.Helper()
	address := nonLoopbackIPv4(t)
	listener, err := net.Listen("tcp4", net.JoinHostPort(address.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	targets := make(chan string, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		request, err := http.ReadRequest(bufio.NewReader(connection))
		if err != nil || request.Method != http.MethodConnect {
			return
		}
		upstream, err := net.DialTimeout("tcp", request.Host, time.Second)
		if err != nil {
			_, _ = io.WriteString(connection, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			return
		}
		defer upstream.Close()
		targets <- request.Host
		if _, err := io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		complete := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(upstream, connection); complete <- struct{}{} }()
		go func() { _, _ = io.Copy(connection, upstream); complete <- struct{}{} }()
		<-complete
	}()
	return listener.Addr().String(), targets
}

func startHangingHTTPConnectProxy(t *testing.T) string {
	t.Helper()
	address := nonLoopbackIPv4(t)
	listener, err := net.Listen("tcp4", net.JoinHostPort(address.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	t.Cleanup(func() {
		close(release)
		_ = listener.Close()
	})
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = http.ReadRequest(bufio.NewReader(connection))
		<-release
	}()
	return listener.Addr().String()
}

func nonLoopbackIPv4(t *testing.T) netip.Addr {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, networkInterface := range interfaces {
		addresses, err := networkInterface.Addrs()
		if err != nil {
			continue
		}
		for _, raw := range addresses {
			prefix, err := netip.ParsePrefix(raw.String())
			if err == nil && prefix.Addr().Is4() && !prefix.Addr().IsLoopback() {
				return prefix.Addr()
			}
		}
	}
	t.Skip("test host has no non-loopback IPv4 address")
	return netip.Addr{}
}

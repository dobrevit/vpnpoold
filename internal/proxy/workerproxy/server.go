package workerproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/dobrevit/microproxy"
	"github.com/dobrevit/vpnpoold/internal/proxy/relay"
)

type Config struct {
	AllowedClientAddress netip.Addr
	UpstreamHTTPProxy    string
	HandshakeTimeout     time.Duration
	ConnectTimeout       time.Duration
	IdleTimeout          time.Duration
	AllowIPv6            bool
}

type Server struct {
	proxy            *microproxy.Server
	handshakeTimeout time.Duration
}

func New(config Config, logger *slog.Logger) (*Server, error) {
	clientAddress := config.AllowedClientAddress.Unmap()
	if !clientAddress.IsValid() || clientAddress.IsUnspecified() || clientAddress.IsMulticast() {
		return nil, errors.New("worker proxy allowed client address is invalid")
	}
	if config.HandshakeTimeout <= 0 || config.ConnectTimeout <= 0 || config.IdleTimeout <= 0 {
		return nil, errors.New("worker proxy timeouts must be positive")
	}

	route := microproxy.Route{}
	upstreamAddress := ""
	if config.UpstreamHTTPProxy != "" {
		parsed, err := parseUpstreamHTTPProxy(config.UpstreamHTTPProxy)
		if err != nil {
			return nil, err
		}
		route.Proxy = parsed
		upstreamAddress = parsed.Host
	}

	options := []microproxy.Option{
		microproxy.WithDialer(outboundDialer{
			timeout: config.ConnectTimeout, allowIPv6: config.AllowIPv6,
			upstreamHTTPProxy: upstreamAddress,
		}),
		// An explicit router prevents HTTP_PROXY inherited from a service
		// environment from changing a namespace worker's egress path.
		microproxy.WithRouter(microproxy.RouterFunc(func(string) (microproxy.Route, error) {
			return route, nil
		})),
	}
	if logger != nil {
		options = append(options, microproxy.WithLogger(
			microproxy.NewSlogLogger(logger, slog.LevelDebug),
		))
	}

	proxy, err := microproxy.New(microproxy.Config{
		AllowedNetworks:     []string{netip.PrefixFrom(clientAddress, clientAddress.BitLen()).String()},
		AllowedConnectPorts: allTCPPorts(),
		ReadTimeout:         config.IdleTimeout,
		WriteTimeout:        config.IdleTimeout,
		ForwardedForHeader:  "delete",
		ViaHeader:           "delete",
	}, options...)
	if err != nil {
		return nil, fmt.Errorf("configure microproxy worker: %w", err)
	}
	return &Server{proxy: proxy, handshakeTimeout: config.HandshakeTimeout}, nil
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if ctx == nil || listener == nil {
		return errors.New("worker proxy context and listener are required")
	}
	wrapped := &workerListener{
		Listener: listener, ctx: ctx, handshakeTimeout: s.handshakeTimeout,
	}
	done := make(chan error, 1)
	go func() { done <- s.proxy.ServeSOCKS(wrapped) }()
	select {
	case err := <-done:
		closeErr := s.proxy.Close()
		if err != nil {
			err = fmt.Errorf("serve microproxy SOCKS frontend: %w", err)
		}
		return errors.Join(err, closeErr)
	case <-ctx.Done():
		closeErr := s.proxy.Close()
		serveErr := <-done
		if serveErr != nil {
			serveErr = fmt.Errorf("stop microproxy SOCKS frontend: %w", serveErr)
		}
		return errors.Join(closeErr, serveErr)
	}
}

func parseUpstreamHTTPProxy(address string) (*url.URL, error) {
	host, portText, err := net.SplitHostPort(address)
	addressIP, addressErr := netip.ParseAddr(host)
	port, portErr := strconv.Atoi(portText)
	if err != nil || addressErr != nil || !addressIP.Is4() ||
		addressIP.IsUnspecified() || addressIP.IsLoopback() || addressIP.IsMulticast() ||
		portErr != nil || port < 1 || port > 65535 {
		return nil, errors.New("upstream HTTP proxy must be an explicit IPv4 address and TCP port")
	}
	return &url.URL{Scheme: "http", Host: address}, nil
}

// microproxy v0.0.1 treats an empty port list as HTTPS-only. vpnpoold has
// historically been a general TCP CONNECT proxy, so enumerate the full valid
// TCP port range to preserve that contract.
func allTCPPorts() []int {
	ports := make([]int, 65535)
	for index := range ports {
		ports[index] = index + 1
	}
	return ports
}

type outboundDialer struct {
	timeout           time.Duration
	allowIPv6         bool
	upstreamHTTPProxy string
}

func (d outboundDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("worker proxy supports TCP connections only")
	}
	if !d.allowIPv6 {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("validate worker proxy destination: %w", err)
		}
		if parsed, parseErr := netip.ParseAddr(host); parseErr == nil && parsed.Is6() {
			return nil, errors.New("IPv6 destinations are disabled")
		}
		network = "tcp4"
	}
	connection, err := (&net.Dialer{Timeout: d.timeout}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if address != d.upstreamHTTPProxy {
		return connection, nil
	}
	deadline := time.Now().Add(d.timeout)
	if err := connection.SetDeadline(deadline); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return &connectHandshakeConn{Conn: connection, deadline: deadline}, nil
}

type workerListener struct {
	net.Listener
	ctx              context.Context
	handshakeTimeout time.Duration
	retryDelay       time.Duration
}

func (l *workerListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err == nil {
			l.retryDelay = 0
			return &handshakeDeadlineConn{
				Conn: connection, deadline: time.Now().Add(l.handshakeTimeout),
			}, nil
		}
		if !relay.IsTemporaryAcceptError(err) {
			return nil, err
		}
		var retry bool
		l.retryDelay, retry = relay.WaitAcceptRetry(l.ctx, l.retryDelay)
		if !retry {
			return nil, net.ErrClosed
		}
	}
}

type handshakeDeadlineConn struct {
	net.Conn
	deadline time.Time
}

func (c *handshakeDeadlineConn) SetDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		deadline = c.deadline
	}
	return c.Conn.SetDeadline(deadline)
}

// connectHandshakeConn keeps the configured connect timeout in force until an
// upstream HTTP proxy has returned its complete CONNECT response header. Once
// that boundary is seen, microproxy's ordinary per-I/O idle deadlines take
// over for the tunnel lifetime.
type connectHandshakeConn struct {
	net.Conn
	deadline time.Time
	matched  int
	complete bool
}

func (c *connectHandshakeConn) Read(data []byte) (int, error) {
	count, err := c.Conn.Read(data)
	if !c.complete {
		const boundary = "\r\n\r\n"
		for _, value := range data[:count] {
			if value == boundary[c.matched] {
				c.matched++
				if c.matched == len(boundary) {
					c.complete = true
					_ = c.Conn.SetDeadline(time.Time{})
					break
				}
			} else if value == boundary[0] {
				c.matched = 1
			} else {
				c.matched = 0
			}
		}
	}
	return count, err
}

func (c *connectHandshakeConn) SetDeadline(deadline time.Time) error {
	if !c.complete && (deadline.IsZero() || deadline.After(c.deadline)) {
		deadline = c.deadline
	}
	return c.Conn.SetDeadline(deadline)
}

func (c *connectHandshakeConn) SetReadDeadline(deadline time.Time) error {
	if !c.complete && (deadline.IsZero() || deadline.After(c.deadline)) {
		deadline = c.deadline
	}
	return c.Conn.SetReadDeadline(deadline)
}

func (c *connectHandshakeConn) SetWriteDeadline(deadline time.Time) error {
	if !c.complete && (deadline.IsZero() || deadline.After(c.deadline)) {
		deadline = c.deadline
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func (c *connectHandshakeConn) CloseRead() error {
	if closer, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return closer.CloseRead()
	}
	return nil
}

func (c *connectHandshakeConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return nil
}

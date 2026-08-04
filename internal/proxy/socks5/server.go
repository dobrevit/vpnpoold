package socks5

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type Config struct {
	HandshakeTimeout time.Duration
	ConnectTimeout   time.Duration
	IdleTimeout      time.Duration
	AllowIPv6        bool
}

type Stats struct {
	ActiveConnections int64
	ConnectionsTotal  uint64
	BytesFromClients  uint64
	BytesToClients    uint64
}

type Server struct {
	config Config
	dialer Dialer
	logger *slog.Logger

	activeConnections atomic.Int64
	connectionsTotal  atomic.Uint64
	bytesFromClients  atomic.Uint64
	bytesToClients    atomic.Uint64

	connectionsMu sync.Mutex
	connections   map[net.Conn]struct{}
	wait          sync.WaitGroup
}

func NewServer(config Config, dialer Dialer, logger *slog.Logger) (*Server, error) {
	if config.HandshakeTimeout <= 0 {
		return nil, errors.New("handshake timeout must be positive")
	}
	if config.ConnectTimeout <= 0 {
		return nil, errors.New("connect timeout must be positive")
	}
	if config.IdleTimeout <= 0 {
		return nil, errors.New("idle timeout must be positive")
	}
	if dialer == nil {
		return nil, errors.New("dialer is required")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Server{
		config:      config,
		dialer:      dialer,
		logger:      logger,
		connections: make(map[net.Conn]struct{}),
	}, nil
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return errors.New("listener is required")
	}
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
			s.closeConnections()
		case <-stop:
		}
	}()
	defer close(stop)

	var temporaryDelay time.Duration
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				s.closeConnections()
				s.wait.Wait()
				return nil
			}
			if isTemporaryAcceptError(err) {
				temporaryDelay = nextAcceptDelay(temporaryDelay)
				timer := time.NewTimer(temporaryDelay)
				select {
				case <-ctx.Done():
					if !timer.Stop() {
						<-timer.C
					}
					continue
				case <-timer.C:
					continue
				}
			}
			s.closeConnections()
			s.wait.Wait()
			return err
		}
		temporaryDelay = 0
		s.track(connection, true)
		s.wait.Add(1)
		go func() {
			defer s.wait.Done()
			defer s.track(connection, false)
			if err := s.ServeConn(ctx, connection); err != nil && ctx.Err() == nil {
				s.logger.Debug("SOCKS5 worker session ended with an error")
			}
		}()
	}
}

func isTemporaryAcceptError(err error) bool {
	var temporary interface{ Temporary() bool }
	return errors.As(err, &temporary) && temporary.Temporary()
}

func nextAcceptDelay(previous time.Duration) time.Duration {
	const (
		minimum = 5 * time.Millisecond
		maximum = time.Second
	)
	if previous <= 0 {
		return minimum
	}
	next := previous * 2
	if next > maximum {
		return maximum
	}
	return next
}

func (s *Server) ServeConn(parent context.Context, client net.Conn) error {
	defer client.Close()
	s.connectionsTotal.Add(1)
	s.activeConnections.Add(1)
	defer s.activeConnections.Add(-1)

	if err := client.SetDeadline(time.Now().Add(s.config.HandshakeTimeout)); err != nil {
		return err
	}
	if err := negotiate(client, client); err != nil {
		return err
	}
	request, replyCode, err := readRequest(client, s.config.AllowIPv6)
	if err != nil {
		_ = writeReply(client, replyCode, nil)
		return err
	}

	dialContext, cancelDial := context.WithTimeout(parent, s.config.ConnectTimeout)
	upstream, err := s.dialer.DialContext(dialContext, "tcp", request.address())
	cancelDial()
	if err != nil {
		_ = writeReply(client, dialErrorReply(err), nil)
		return err
	}
	defer upstream.Close()
	if err := writeReply(client, replySucceeded, upstream.LocalAddr()); err != nil {
		return err
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		return err
	}

	sessionContext, cancelSession := context.WithCancel(parent)
	defer cancelSession()
	go func() {
		<-sessionContext.Done()
		_ = client.Close()
		_ = upstream.Close()
	}()

	clientWithDeadline := deadlineConn{Conn: client, timeout: s.config.IdleTimeout}
	upstreamWithDeadline := deadlineConn{Conn: upstream, timeout: s.config.IdleTimeout}
	results := make(chan copyResult, 2)
	go copyStream(results, "from_client", upstreamWithDeadline, clientWithDeadline)
	go copyStream(results, "to_client", clientWithDeadline, upstreamWithDeadline)

	first := <-results
	s.recordBytes(first)
	halfClose(first.direction, client, upstream)
	second := <-results
	s.recordBytes(second)
	cancelSession()

	if significantCopyError(first.err) {
		return first.err
	}
	if significantCopyError(second.err) {
		return second.err
	}
	return nil
}

func (s *Server) Stats() Stats {
	return Stats{
		ActiveConnections: s.activeConnections.Load(),
		ConnectionsTotal:  s.connectionsTotal.Load(),
		BytesFromClients:  s.bytesFromClients.Load(),
		BytesToClients:    s.bytesToClients.Load(),
	}
}

func (s *Server) track(connection net.Conn, add bool) {
	s.connectionsMu.Lock()
	defer s.connectionsMu.Unlock()
	if add {
		s.connections[connection] = struct{}{}
	} else {
		delete(s.connections, connection)
	}
}

func (s *Server) closeConnections() {
	s.connectionsMu.Lock()
	defer s.connectionsMu.Unlock()
	for connection := range s.connections {
		_ = connection.Close()
	}
}

func (s *Server) recordBytes(result copyResult) {
	if result.direction == "from_client" {
		s.bytesFromClients.Add(uint64(result.bytes))
	} else {
		s.bytesToClients.Add(uint64(result.bytes))
	}
}

type copyResult struct {
	direction string
	bytes     int64
	err       error
}

func copyStream(results chan<- copyResult, direction string, destination io.Writer, source io.Reader) {
	count, err := io.Copy(destination, source)
	results <- copyResult{direction: direction, bytes: count, err: err}
}

func halfClose(direction string, client, upstream net.Conn) {
	if direction == "from_client" {
		if connection, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = connection.CloseWrite()
		}
		if connection, ok := client.(interface{ CloseRead() error }); ok {
			_ = connection.CloseRead()
		}
		return
	}
	if connection, ok := client.(interface{ CloseWrite() error }); ok {
		_ = connection.CloseWrite()
	}
	if connection, ok := upstream.(interface{ CloseRead() error }); ok {
		_ = connection.CloseRead()
	}
}

func significantCopyError(err error) bool {
	return err != nil &&
		!errors.Is(err, net.ErrClosed) &&
		!errors.Is(err, io.EOF) &&
		!errors.Is(err, context.Canceled)
}

func dialErrorReply(err error) byte {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return replyConnectionRefused
	}
	if errors.Is(err, syscall.ENETUNREACH) {
		return replyNetworkUnreachable
	}
	if errors.Is(err, syscall.EHOSTUNREACH) {
		return replyHostUnreachable
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return replyHostUnreachable
	}
	return replyGeneralFailure
}

type deadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (c deadlineConn) Read(data []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Read(data)
}

func (c deadlineConn) Write(data []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(data)
}

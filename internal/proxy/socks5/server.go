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

	"github.com/dobrevit/vpnpoold/internal/proxy/relay"
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
			if relay.IsTemporaryAcceptError(err) {
				temporaryDelay, _ = relay.WaitAcceptRetry(ctx, temporaryDelay)
				continue
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

	return relay.Bidirectional(parent, client, upstream, s.config.IdleTimeout, s.recordBytes)
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

func (s *Server) recordBytes(result relay.Result) {
	if result.Direction == relay.FromClient {
		s.bytesFromClients.Add(uint64(result.Bytes))
	} else {
		s.bytesToClients.Add(uint64(result.Bytes))
	}
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

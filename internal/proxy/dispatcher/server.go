package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dobrevit/vpnpoold/internal/balance"
	"github.com/dobrevit/vpnpoold/internal/proxy/relay"
	"github.com/dobrevit/vpnpoold/internal/proxy/socks5"
)

const usernamePasswordVersion = 0x01

type Authenticator interface {
	Authenticate(username string, password []byte) bool
}

type Connector interface {
	Connect(context.Context, balance.Candidate, string) (net.Conn, error)
}

type SOCKSConnector struct {
	NetDialer        socks5.Dialer
	HandshakeTimeout time.Duration
}

func (c SOCKSConnector) Connect(
	ctx context.Context,
	candidate balance.Candidate,
	destination string,
) (net.Conn, error) {
	dialer := socks5.ClientDialer{
		ProxyAddress:     candidate.Address,
		NetDialer:        c.NetDialer,
		HandshakeTimeout: c.HandshakeTimeout,
	}
	return dialer.DialContext(ctx, "tcp", destination)
}

type Config struct {
	Mode               balance.Mode
	SessionSeparator   string
	HandshakeTimeout   time.Duration
	ConnectTimeout     time.Duration
	IdleTimeout        time.Duration
	AllowIPv6          bool
	MaxConnectAttempts int
}

type Stats struct {
	ActiveConnections      int64
	ConnectionsTotal       uint64
	AuthenticationFailures uint64
	BackendSelections      uint64
	BackendRetries         uint64
	NoWorkerFailures       uint64
	BytesFromClients       uint64
	BytesToClients         uint64
}

type WorkerStats struct {
	ConnectionsTotal  uint64
	BackendSelections uint64
	BytesFromClients  uint64
	BytesToClients    uint64
}

type workerCounters struct {
	connectionsTotal  atomic.Uint64
	backendSelections atomic.Uint64
	bytesFromClients  atomic.Uint64
	bytesToClients    atomic.Uint64
}

type Dispatcher struct {
	config        Config
	pool          Pool
	selector      *balance.Selector
	connector     Connector
	authenticator Authenticator
	logger        *slog.Logger

	activeConnections      atomic.Int64
	connectionsTotal       atomic.Uint64
	authenticationFailures atomic.Uint64
	backendSelections      atomic.Uint64
	backendRetries         atomic.Uint64
	noWorkerFailures       atomic.Uint64
	bytesFromClients       atomic.Uint64
	bytesToClients         atomic.Uint64

	mu          sync.Mutex
	connections map[net.Conn]struct{}
	sessions    map[*activeSession]struct{}
	workerStats map[string]*workerCounters
	wait        sync.WaitGroup
}

type activeSession struct {
	workerID string
	client   net.Conn
	upstream net.Conn
}

func New(
	config Config,
	pool Pool,
	connector Connector,
	authenticator Authenticator,
	logger *slog.Logger,
) (*Dispatcher, error) {
	if pool == nil {
		return nil, errors.New("worker pool is required")
	}
	if connector == nil {
		return nil, errors.New("backend connector is required")
	}
	if config.HandshakeTimeout <= 0 || config.ConnectTimeout <= 0 || config.IdleTimeout <= 0 {
		return nil, errors.New("dispatcher timeouts must be positive")
	}
	switch config.Mode {
	case balance.RoundRobin, balance.LeastConnections, balance.SourceHash:
	case balance.UsernameHash, balance.SessionHash:
		if authenticator == nil {
			return nil, errors.New("username and session hashing require authentication")
		}
	default:
		return nil, errors.New("dispatcher balancing mode is unsupported")
	}
	if config.SessionSeparator == "" || len(config.SessionSeparator) > 8 {
		return nil, errors.New("session separator must contain between 1 and 8 bytes")
	}
	if config.MaxConnectAttempts < 0 {
		return nil, errors.New("maximum connect attempts must not be negative")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Dispatcher{
		config:        config,
		pool:          pool,
		selector:      &balance.Selector{},
		connector:     connector,
		authenticator: authenticator,
		logger:        logger,
		connections:   make(map[net.Conn]struct{}),
		sessions:      make(map[*activeSession]struct{}),
		workerStats:   make(map[string]*workerCounters),
	}, nil
}

func (d *Dispatcher) Serve(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return errors.New("listener is required")
	}
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
			d.closeAll()
		case <-stop:
		}
	}()
	defer close(stop)

	var temporaryDelay time.Duration
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				d.closeAll()
				d.wait.Wait()
				return nil
			}
			if relay.IsTemporaryAcceptError(err) {
				temporaryDelay, _ = relay.WaitAcceptRetry(ctx, temporaryDelay)
				continue
			}
			d.closeAll()
			d.wait.Wait()
			return fmt.Errorf("accept dispatcher connection: %w", err)
		}
		temporaryDelay = 0
		d.trackConnection(connection, true)
		d.wait.Add(1)
		go func() {
			defer d.wait.Done()
			defer d.trackConnection(connection, false)
			if err := d.ServeConn(ctx, connection); err != nil && ctx.Err() == nil {
				d.logger.Debug("dispatcher session ended with an error")
			}
		}()
	}
}

func (d *Dispatcher) ServeConn(parent context.Context, client net.Conn) error {
	defer client.Close()
	d.connectionsTotal.Add(1)
	d.activeConnections.Add(1)
	defer d.activeConnections.Add(-1)

	if err := client.SetDeadline(time.Now().Add(d.config.HandshakeTimeout)); err != nil {
		return err
	}
	identity, err := d.authenticate(client)
	if err != nil {
		return err
	}
	request, replyCode, err := socks5.ReadConnectRequest(client, d.config.AllowIPv6)
	if err != nil {
		_ = socks5.WriteConnectReply(client, replyCode, nil)
		return err
	}

	key, err := d.selectionKey(client.RemoteAddr(), identity)
	if err != nil {
		_ = socks5.WriteConnectReply(client, socks5.ReplyGeneralFailure, nil)
		return err
	}
	upstream, selected, replyCode, err := d.connect(parent, key, request.Address())
	if err != nil {
		_ = socks5.WriteConnectReply(client, replyCode, nil)
		return err
	}
	defer upstream.Close()
	defer d.pool.Release(selected.ID)
	d.workerCounters(selected.ID).connectionsTotal.Add(1)
	session := &activeSession{workerID: selected.ID, client: client, upstream: upstream}
	d.trackSession(session, true)
	defer d.trackSession(session, false)

	// This acknowledgement is the retry boundary. No subsequent error may
	// select another worker for this client connection.
	if err := socks5.WriteConnectReply(client, socks5.ReplySucceeded, upstream.LocalAddr()); err != nil {
		return err
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		return err
	}

	return d.relay(parent, selected.ID, client, upstream)
}

func (d *Dispatcher) authenticate(connection net.Conn) (identity, error) {
	methods, err := socks5.ReadMethods(connection)
	if err != nil {
		return identity{}, err
	}
	required := byte(socks5.MethodNoAuthentication)
	if d.authenticator != nil {
		required = socks5.MethodUsernamePassword
	}
	if !socks5.OffersMethod(methods, required) {
		_ = socks5.WriteMethodSelection(connection, socks5.MethodNoAcceptable)
		return identity{}, errors.New("client did not offer the required SOCKS5 authentication method")
	}
	if err := socks5.WriteMethodSelection(connection, required); err != nil {
		return identity{}, err
	}
	if d.authenticator == nil {
		return identity{}, nil
	}

	rawUsername, password, err := readUsernamePassword(connection)
	if err != nil {
		d.authenticationFailures.Add(1)
		_ = writeAuthenticationReply(connection, false)
		return identity{}, err
	}
	defer clear(password)
	parsed, err := parseIdentity(rawUsername, d.config.SessionSeparator)
	if err != nil || !d.authenticator.Authenticate(parsed.username, password) {
		d.authenticationFailures.Add(1)
		_ = writeAuthenticationReply(connection, false)
		return identity{}, errors.New("SOCKS5 authentication failed")
	}
	if err := writeAuthenticationReply(connection, true); err != nil {
		return identity{}, err
	}
	return parsed, nil
}

func (d *Dispatcher) selectionKey(remote net.Addr, identity identity) (string, error) {
	switch d.config.Mode {
	case balance.RoundRobin, balance.LeastConnections:
		return "", nil
	case balance.SourceHash:
		host, _, err := net.SplitHostPort(remote.String())
		if err != nil || host == "" {
			return "", errors.New("client source address is unavailable for source hashing")
		}
		return host, nil
	case balance.UsernameHash:
		if identity.username == "" {
			return "", errors.New("authenticated username is unavailable")
		}
		return identity.username, nil
	case balance.SessionHash:
		if identity.session == "" {
			return "", errors.New("session_hash requires username/session-id authentication")
		}
		return identity.session, nil
	default:
		return "", errors.New("balancing mode is unsupported")
	}
}

func (d *Dispatcher) connect(
	parent context.Context,
	key string,
	destination string,
) (net.Conn, balance.Candidate, byte, error) {
	candidates := d.pool.Snapshot()
	maxAttempts := len(candidates)
	if d.config.MaxConnectAttempts > 0 && d.config.MaxConnectAttempts < maxAttempts {
		maxAttempts = d.config.MaxConnectAttempts
	}
	attempts := 0
	var lastErr error
	lastReply := byte(socks5.ReplyHostUnreachable)
	for attempts < maxAttempts && len(candidates) > 0 {
		selected, err := d.selector.Select(d.config.Mode, key, candidates)
		if err != nil {
			d.noWorkerFailures.Add(1)
			return nil, balance.Candidate{}, socks5.ReplyHostUnreachable, err
		}
		acquired, ok := d.pool.Acquire(selected.ID, selected.Generation)
		candidates = withoutCandidate(candidates, selected.ID)
		if !ok {
			continue
		}
		attempts++
		d.backendSelections.Add(1)
		d.workerCounters(acquired.ID).backendSelections.Add(1)
		connectContext, cancel := context.WithTimeout(parent, d.config.ConnectTimeout)
		connection, connectErr := d.connector.Connect(connectContext, acquired, destination)
		cancel()
		if connectErr == nil {
			return connection, acquired, socks5.ReplySucceeded, nil
		}
		d.pool.Release(acquired.ID)
		lastErr = connectErr
		var replyErr *socks5.ReplyError
		if errors.As(connectErr, &replyErr) {
			// The worker successfully carried the request and reported a
			// destination failure. Trying another exit would duplicate the
			// application attempt and violate the single-worker boundary.
			return nil, balance.Candidate{}, replyErr.Code, connectErr
		} else {
			lastReply = socks5.ReplyGeneralFailure
			if d.pool.ReportFailure(acquired.ID, acquired.Generation, connectErr) {
				d.CloseWorkerSessions(acquired.ID)
			}
		}
		if attempts < maxAttempts && len(candidates) > 0 {
			d.backendRetries.Add(1)
		}
	}
	if lastErr == nil {
		d.noWorkerFailures.Add(1)
		lastErr = errors.New("no healthy undrained workers are available")
	}
	return nil, balance.Candidate{}, lastReply, lastErr
}

func (d *Dispatcher) relay(parent context.Context, workerID string, client, upstream net.Conn) error {
	return relay.Bidirectional(
		parent, client, upstream, d.config.IdleTimeout,
		func(result relay.Result) { d.recordBytes(workerID, result) },
	)
}

func (d *Dispatcher) CloseWorkerSessions(workerID string) int {
	d.mu.Lock()
	var sessions []*activeSession
	for session := range d.sessions {
		if session.workerID == workerID {
			sessions = append(sessions, session)
		}
	}
	d.mu.Unlock()
	for _, session := range sessions {
		_ = session.client.Close()
		_ = session.upstream.Close()
	}
	return len(sessions)
}

func (d *Dispatcher) Stats() Stats {
	return Stats{
		ActiveConnections:      d.activeConnections.Load(),
		ConnectionsTotal:       d.connectionsTotal.Load(),
		AuthenticationFailures: d.authenticationFailures.Load(),
		BackendSelections:      d.backendSelections.Load(),
		BackendRetries:         d.backendRetries.Load(),
		NoWorkerFailures:       d.noWorkerFailures.Load(),
		BytesFromClients:       d.bytesFromClients.Load(),
		BytesToClients:         d.bytesToClients.Load(),
	}
}

func (d *Dispatcher) WorkerStats() map[string]WorkerStats {
	d.mu.Lock()
	counters := make(map[string]*workerCounters, len(d.workerStats))
	for workerID, current := range d.workerStats {
		counters[workerID] = current
	}
	d.mu.Unlock()

	result := make(map[string]WorkerStats, len(counters))
	for workerID, current := range counters {
		result[workerID] = WorkerStats{
			ConnectionsTotal:  current.connectionsTotal.Load(),
			BackendSelections: current.backendSelections.Load(),
			BytesFromClients:  current.bytesFromClients.Load(),
			BytesToClients:    current.bytesToClients.Load(),
		}
	}
	return result
}

func (d *Dispatcher) workerCounters(workerID string) *workerCounters {
	d.mu.Lock()
	defer d.mu.Unlock()
	counters := d.workerStats[workerID]
	if counters == nil {
		counters = &workerCounters{}
		d.workerStats[workerID] = counters
	}
	return counters
}

func (d *Dispatcher) trackConnection(connection net.Conn, add bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if add {
		d.connections[connection] = struct{}{}
	} else {
		delete(d.connections, connection)
	}
}

func (d *Dispatcher) trackSession(session *activeSession, add bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if add {
		d.sessions[session] = struct{}{}
	} else {
		delete(d.sessions, session)
	}
}

func (d *Dispatcher) closeAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for connection := range d.connections {
		_ = connection.Close()
	}
	for session := range d.sessions {
		_ = session.upstream.Close()
	}
}

func withoutCandidate(candidates []balance.Candidate, id string) []balance.Candidate {
	result := make([]balance.Candidate, 0, len(candidates)-1)
	for _, candidate := range candidates {
		if candidate.ID != id {
			result = append(result, candidate)
		}
	}
	return result
}

type identity struct {
	username string
	session  string
}

func parseIdentity(raw, separator string) (identity, error) {
	if raw == "" {
		return identity{}, errors.New("SOCKS5 username is empty")
	}
	parts := strings.SplitN(raw, separator, 2)
	result := identity{username: parts[0]}
	if result.username == "" {
		return identity{}, errors.New("SOCKS5 username is empty")
	}
	if len(parts) == 2 {
		if parts[1] == "" {
			return identity{}, errors.New("SOCKS5 session identifier is empty")
		}
		result.session = parts[1]
	}
	return result, nil
}

func readUsernamePassword(reader io.Reader) (string, []byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return "", nil, errors.New("read SOCKS5 username authentication header")
	}
	if header[0] != usernamePasswordVersion || header[1] == 0 {
		return "", nil, errors.New("invalid SOCKS5 username authentication header")
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, username); err != nil {
		return "", nil, errors.New("read SOCKS5 username")
	}
	var passwordLength [1]byte
	if _, err := io.ReadFull(reader, passwordLength[:]); err != nil || passwordLength[0] == 0 {
		return "", nil, errors.New("invalid SOCKS5 password length")
	}
	password := make([]byte, int(passwordLength[0]))
	if _, err := io.ReadFull(reader, password); err != nil {
		clear(password)
		return "", nil, errors.New("read SOCKS5 password")
	}
	return string(username), password, nil
}

func writeAuthenticationReply(writer io.Writer, success bool) error {
	status := byte(0x01)
	if success {
		status = 0x00
	}
	_, err := writer.Write([]byte{usernamePasswordVersion, status})
	return err
}

func (d *Dispatcher) recordBytes(workerID string, result relay.Result) {
	counters := d.workerCounters(workerID)
	if result.Direction == relay.FromClient {
		d.bytesFromClients.Add(uint64(result.Bytes))
		counters.bytesFromClients.Add(uint64(result.Bytes))
	} else {
		d.bytesToClients.Add(uint64(result.Bytes))
		counters.bytesToClients.Add(uint64(result.Bytes))
	}
}

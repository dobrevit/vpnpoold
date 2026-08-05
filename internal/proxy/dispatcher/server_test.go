package dispatcher

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dobrevit/vpnpoold/internal/balance"
	"github.com/dobrevit/vpnpoold/internal/proxy/socks5"
	"github.com/dobrevit/vpnpoold/internal/proxy/workerproxy"
)

func TestDispatcherRelaysThroughSelectedWorker(t *testing.T) {
	destination := startEchoServer(t)
	workerAddress := startWorker(t)
	registry := NewRegistry()
	mustUpsert(t, registry, balance.Candidate{
		ID: "worker-1", Address: workerAddress, Weight: 1, Healthy: true,
	})
	connector := &recordingConnector{delegate: SOCKSConnector{
		NetDialer: &net.Dialer{}, HandshakeTimeout: time.Second,
	}}
	dispatcher := newTestDispatcher(t, registry, connector, nil, balance.LeastConnections)
	address, stop := startDispatcher(t, dispatcher)
	defer stop()

	client := dialDispatcher(t, address, "", "", destination)
	payload := []byte("through selected worker")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != string(payload) {
		t.Fatalf("reply = %q", reply)
	}
	_ = client.Close()
	if got := connector.workerIDs(); len(got) != 1 || got[0] != "worker-1" {
		t.Fatalf("selected workers = %v", got)
	}
	deadline := time.Now().Add(time.Second)
	for {
		stats := dispatcher.WorkerStats()["worker-1"]
		if stats.ConnectionsTotal == 1 &&
			stats.BackendSelections == 1 &&
			stats.BytesFromClients == uint64(len(payload)) &&
			stats.BytesToClients == uint64(len(payload)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("worker stats = %+v", stats)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDispatcherAuthenticatesAndSessionHashIsStable(t *testing.T) {
	destination := startEchoServer(t)
	registry := NewRegistry()
	for _, candidate := range []balance.Candidate{
		{ID: "worker-a", Address: startWorker(t), Weight: 1, Healthy: true},
		{ID: "worker-b", Address: startWorker(t), Weight: 1, Healthy: true},
	} {
		mustUpsert(t, registry, candidate)
	}
	connector := &recordingConnector{delegate: SOCKSConnector{
		NetDialer: &net.Dialer{}, HandshakeTimeout: time.Second,
	}}
	authenticator := staticAuthenticator{username: "alice", password: "secret"}
	dispatcher := newTestDispatcher(t, registry, connector, authenticator, balance.SessionHash)
	address, stop := startDispatcher(t, dispatcher)
	defer stop()

	for index := 0; index < 2; index++ {
		client := dialDispatcher(t, address, "alice/session-123", "secret", destination)
		_ = client.Close()
	}
	selected := connector.workerIDs()
	if len(selected) != 2 || selected[0] != selected[1] {
		t.Fatalf("session hash selections = %v", selected)
	}

	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	authenticateOnly(t, connection, "alice/session-123", "wrong")
	var authReply [2]byte
	if _, err := io.ReadFull(connection, authReply[:]); err != nil {
		t.Fatal(err)
	}
	if authReply != [2]byte{1, 1} {
		t.Fatalf("authentication reply = %v", authReply)
	}
	if dispatcher.Stats().AuthenticationFailures != 1 {
		t.Fatalf("authentication failures = %d", dispatcher.Stats().AuthenticationFailures)
	}
}

func TestDispatcherRetriesOnlyBeforeAcknowledgement(t *testing.T) {
	destination := startEchoServer(t)
	registry := NewRegistry()
	mustUpsert(t, registry, balance.Candidate{
		ID: "worker-a", Address: "10.0.0.2:1081", Weight: 1, Healthy: true,
	})
	mustUpsert(t, registry, balance.Candidate{
		ID: "worker-b", Address: "10.0.0.6:1081", Weight: 1, Healthy: true,
	})
	connector := &failThenDirectConnector{failWorker: "worker-a"}
	dispatcher := newTestDispatcher(t, registry, connector, nil, balance.RoundRobin)
	address, stop := startDispatcher(t, dispatcher)
	defer stop()

	client := dialDispatcher(t, address, "", "", destination)
	defer client.Close()
	payload := []byte("retried safely")
	_, _ = client.Write(payload)
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if connector.callCount() != 2 {
		t.Fatalf("connector calls = %d", connector.callCount())
	}
	if registryCandidate(t, registry, "worker-a").Healthy {
		t.Fatal("transport-failed worker remained healthy")
	}
	stats := dispatcher.Stats()
	if stats.BackendRetries != 1 || stats.BackendSelections != 2 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestStaleSelectionDoesNotConsumeConnectAttempt(t *testing.T) {
	destination := startEchoServer(t)
	registry := NewRegistry()
	mustUpsert(t, registry, balance.Candidate{
		ID: "worker-a", Address: "10.0.0.2:1081", Weight: 1, Healthy: true,
	})
	mustUpsert(t, registry, balance.Candidate{
		ID: "worker-b", Address: "10.0.0.6:1081", Weight: 1, Healthy: true,
	})
	pool := &rejectAcquirePool{Pool: registry, rejectID: "worker-a"}
	connector := &failThenDirectConnector{}
	dispatcher := newTestDispatcher(t, pool, connector, nil, balance.RoundRobin)
	dispatcher.config.MaxConnectAttempts = 1
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- dispatcher.ServeConn(context.Background(), server) }()
	performNoAuthGreeting(t, client)
	writeConnectRequest(t, client, destination)
	if code := readConnectReply(t, client); code != socks5.ReplySucceeded {
		t.Fatalf("reply code = %d", code)
	}
	_ = client.Close()
	<-done
	if connector.callCount() != 1 {
		t.Fatalf("connector calls = %d", connector.callCount())
	}
}

func TestDestinationFailureDoesNotMarkWorkerUnhealthy(t *testing.T) {
	registry := NewRegistry()
	for _, candidate := range []balance.Candidate{
		{ID: "worker-a", Address: "10.0.0.2:1081", Weight: 1, Healthy: true},
		{ID: "worker-b", Address: "10.0.0.6:1081", Weight: 1, Healthy: true},
	} {
		mustUpsert(t, registry, candidate)
	}
	var calls int
	connector := connectorFunc(func(context.Context, balance.Candidate, string) (net.Conn, error) {
		calls++
		return nil, &socks5.ReplyError{Code: socks5.ReplyConnectionRefused}
	})
	dispatcher := newTestDispatcher(t, registry, connector, nil, balance.RoundRobin)
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- dispatcher.ServeConn(context.Background(), server) }()
	performNoAuthGreeting(t, client)
	writeConnectRequest(t, client, "127.0.0.1:9")
	if code := readConnectReply(t, client); code != socks5.ReplyConnectionRefused {
		t.Fatalf("reply code = %d", code)
	}
	_ = client.Close()
	<-done
	if !registryCandidate(t, registry, "worker-a").Healthy {
		t.Fatal("ordinary destination refusal marked worker unhealthy")
	}
	if calls != 1 || dispatcher.Stats().BackendRetries != 0 {
		t.Fatalf("destination failure calls = %d, stats = %+v", calls, dispatcher.Stats())
	}
}

func TestDispatcherDoesNotMigrateAcknowledgedSession(t *testing.T) {
	registry := NewRegistry()
	for _, id := range []string{"worker-a", "worker-b"} {
		mustUpsert(t, registry, balance.Candidate{
			ID: id, Address: id + ":1081", Weight: 1, Healthy: true,
		})
	}
	connector := &closingConnector{}
	dispatcher := newTestDispatcher(t, registry, connector, nil, balance.RoundRobin)
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- dispatcher.ServeConn(context.Background(), server) }()
	performNoAuthGreeting(t, client)
	writeConnectRequest(t, client, "127.0.0.1:80")
	if code := readConnectReply(t, client); code != socks5.ReplySucceeded {
		t.Fatalf("reply code = %d", code)
	}
	buffer := make([]byte, 1)
	_, _ = client.Read(buffer)
	_ = client.Close()
	<-done
	if connector.calls != 1 {
		t.Fatalf("acknowledged session was retried %d time(s)", connector.calls)
	}
}

func TestCloseWorkerSessionsTerminatesPinnedConnection(t *testing.T) {
	registry := NewRegistry()
	mustUpsert(t, registry, balance.Candidate{
		ID: "worker-a", Address: "worker-a:1081", Weight: 1, Healthy: true,
	})
	connector := &heldConnector{ready: make(chan struct{})}
	dispatcher := newTestDispatcher(t, registry, connector, nil, balance.RoundRobin)
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- dispatcher.ServeConn(context.Background(), server) }()
	performNoAuthGreeting(t, client)
	writeConnectRequest(t, client, "127.0.0.1:80")
	if code := readConnectReply(t, client); code != socks5.ReplySucceeded {
		t.Fatalf("reply code = %d", code)
	}
	<-connector.ready
	deadline := time.Now().Add(time.Second)
	closed := 0
	for closed == 0 && time.Now().Before(deadline) {
		closed = dispatcher.CloseWorkerSessions("worker-a")
		if closed == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	if closed != 1 {
		t.Fatalf("closed sessions = %d", closed)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("client remained connected after worker failure")
	}
	_ = client.Close()
	<-done
}

func TestCloseWorkerSessionsOwnsConnectionBeforeSuccessReply(t *testing.T) {
	registry := NewRegistry()
	mustUpsert(t, registry, balance.Candidate{
		ID: "worker-a", Address: "worker-a:1081", Weight: 1, Healthy: true,
	})
	connector := &heldConnector{ready: make(chan struct{})}
	dispatcher := newTestDispatcher(t, registry, connector, nil, balance.RoundRobin)
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- dispatcher.ServeConn(context.Background(), server) }()
	performNoAuthGreeting(t, client)
	writeConnectRequest(t, client, "127.0.0.1:80")
	<-connector.ready

	deadline := time.Now().Add(time.Second)
	closed := 0
	for closed == 0 && time.Now().Before(deadline) {
		closed = dispatcher.CloseWorkerSessions("worker-a")
		time.Sleep(time.Millisecond)
	}
	if closed != 1 {
		t.Fatalf("closed sessions before success reply = %d", closed)
	}
	_ = client.Close()
	if err := <-done; err == nil {
		t.Fatal("session succeeded after worker was withdrawn before acknowledgement")
	}
}

func TestDispatcherBacksOffAfterTemporaryAcceptFailure(t *testing.T) {
	registry := NewRegistry()
	dispatcher := newTestDispatcher(
		t,
		registry,
		connectorFunc(func(context.Context, balance.Candidate, string) (net.Conn, error) {
			return nil, errors.New("unused")
		}),
		nil,
		balance.RoundRobin,
	)
	listener := &acceptErrorListener{errors: []error{
		temporaryAcceptError{},
		errors.New("permanent accept failure"),
	}}
	started := time.Now()
	err := dispatcher.Serve(context.Background(), listener)
	if err == nil || !strings.Contains(err.Error(), "permanent accept failure") {
		t.Fatalf("Serve() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed < 5*time.Millisecond {
		t.Fatalf("temporary accept retry spun without backoff: %v", elapsed)
	}
}

func newTestDispatcher(
	t *testing.T,
	pool Pool,
	connector Connector,
	authenticator Authenticator,
	mode balance.Mode,
) *Dispatcher {
	t.Helper()
	server, err := New(Config{
		Mode:               mode,
		SessionSeparator:   "/",
		HandshakeTimeout:   time.Second,
		ConnectTimeout:     time.Second,
		IdleTimeout:        time.Second,
		MaxConnectAttempts: 0,
	}, pool, connector, authenticator, nil)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func startDispatcher(t *testing.T, dispatcher *Dispatcher) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dispatcher.Serve(ctx, listener) }()
	return listener.Addr().String(), func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve() error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("dispatcher did not stop")
		}
	}
}

func startWorker(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := workerproxy.New(workerproxy.Config{
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
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return listener.Addr().String()
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

func dialDispatcher(t *testing.T, address, username, password, destination string) net.Conn {
	t.Helper()
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	if username == "" {
		performNoAuthGreeting(t, connection)
	} else {
		authenticateOnly(t, connection, username, password)
		var reply [2]byte
		if _, err := io.ReadFull(connection, reply[:]); err != nil {
			t.Fatal(err)
		}
		if reply != [2]byte{1, 0} {
			t.Fatalf("authentication reply = %v", reply)
		}
	}
	writeConnectRequest(t, connection, destination)
	if code := readConnectReply(t, connection); code != socks5.ReplySucceeded {
		t.Fatalf("CONNECT reply = %d", code)
	}
	return connection
}

func performNoAuthGreeting(t *testing.T, connection net.Conn) {
	t.Helper()
	_, _ = connection.Write([]byte{5, 1, socks5.MethodNoAuthentication})
	var reply [2]byte
	if _, err := io.ReadFull(connection, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply != [2]byte{5, socks5.MethodNoAuthentication} {
		t.Fatalf("method reply = %v", reply)
	}
}

func authenticateOnly(t *testing.T, connection net.Conn, username, password string) {
	t.Helper()
	_, _ = connection.Write([]byte{5, 1, socks5.MethodUsernamePassword})
	var method [2]byte
	if _, err := io.ReadFull(connection, method[:]); err != nil {
		t.Fatal(err)
	}
	if method != [2]byte{5, socks5.MethodUsernamePassword} {
		t.Fatalf("method reply = %v", method)
	}
	request := []byte{1, byte(len(username))}
	request = append(request, username...)
	request = append(request, byte(len(password)))
	request = append(request, password...)
	_, _ = connection.Write(request)
}

func writeConnectRequest(t *testing.T, connection net.Conn, destination string) {
	t.Helper()
	host, portText, err := net.SplitHostPort(destination)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	request := []byte{5, 1, 0, 3, byte(len(host))}
	request = append(request, host...)
	var rawPort [2]byte
	binary.BigEndian.PutUint16(rawPort[:], uint16(port))
	request = append(request, rawPort[:]...)
	_, _ = connection.Write(request)
}

func readConnectReply(t *testing.T, connection net.Conn) byte {
	t.Helper()
	var header [4]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		t.Fatal(err)
	}
	length := 0
	switch header[3] {
	case 1:
		length = 4
	case 4:
		length = 16
	default:
		t.Fatalf("unexpected address type %d", header[3])
	}
	if _, err := io.CopyN(io.Discard, connection, int64(length+2)); err != nil {
		t.Fatal(err)
	}
	return header[1]
}

func mustUpsert(t *testing.T, registry *Registry, candidate balance.Candidate) {
	t.Helper()
	if err := registry.Upsert(candidate); err != nil {
		t.Fatal(err)
	}
}

func registryCandidate(t *testing.T, registry *Registry, id string) balance.Candidate {
	t.Helper()
	for _, candidate := range registry.Snapshot() {
		if candidate.ID == id {
			return candidate
		}
	}
	t.Fatalf("candidate %q not found", id)
	return balance.Candidate{}
}

type staticAuthenticator struct {
	username string
	password string
}

type temporaryAcceptError struct{}

func (temporaryAcceptError) Error() string   { return "temporary accept failure" }
func (temporaryAcceptError) Timeout() bool   { return false }
func (temporaryAcceptError) Temporary() bool { return true }

type acceptErrorListener struct {
	errors []error
	index  int
}

func (l *acceptErrorListener) Accept() (net.Conn, error) {
	if l.index >= len(l.errors) {
		return nil, net.ErrClosed
	}
	err := l.errors[l.index]
	l.index++
	return nil, err
}

func (*acceptErrorListener) Close() error   { return nil }
func (*acceptErrorListener) Addr() net.Addr { return &net.TCPAddr{} }

func (a staticAuthenticator) Authenticate(username string, password []byte) bool {
	return username == a.username && string(password) == a.password
}

type recordingConnector struct {
	mu       sync.Mutex
	delegate Connector
	selected []string
}

func (c *recordingConnector) Connect(
	ctx context.Context,
	candidate balance.Candidate,
	destination string,
) (net.Conn, error) {
	c.mu.Lock()
	c.selected = append(c.selected, candidate.ID)
	c.mu.Unlock()
	return c.delegate.Connect(ctx, candidate, destination)
}

func (c *recordingConnector) workerIDs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.selected...)
}

type failThenDirectConnector struct {
	mu         sync.Mutex
	failWorker string
	calls      int
}

func (c *failThenDirectConnector) Connect(
	ctx context.Context,
	candidate balance.Candidate,
	destination string,
) (net.Conn, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	if candidate.ID == c.failWorker {
		return nil, errors.New("worker transport failed")
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", destination)
}

func (c *failThenDirectConnector) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

type connectorFunc func(context.Context, balance.Candidate, string) (net.Conn, error)

func (f connectorFunc) Connect(
	ctx context.Context,
	candidate balance.Candidate,
	destination string,
) (net.Conn, error) {
	return f(ctx, candidate, destination)
}

type closingConnector struct {
	calls int
}

func (c *closingConnector) Connect(context.Context, balance.Candidate, string) (net.Conn, error) {
	c.calls++
	server, peer := net.Pipe()
	_ = peer.Close()
	return server, nil
}

type heldConnector struct {
	ready chan struct{}
	once  sync.Once
	peers []net.Conn
	mu    sync.Mutex
}

type rejectAcquirePool struct {
	Pool
	rejectID string
}

func (p *rejectAcquirePool) Acquire(id string, generation uint64) (balance.Candidate, bool) {
	if id == p.rejectID {
		return balance.Candidate{}, false
	}
	return p.Pool.Acquire(id, generation)
}

func (c *heldConnector) Connect(context.Context, balance.Candidate, string) (net.Conn, error) {
	server, peer := net.Pipe()
	c.mu.Lock()
	c.peers = append(c.peers, peer)
	c.mu.Unlock()
	c.once.Do(func() { close(c.ready) })
	return server, nil
}

package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestServerConnectAndRelay(t *testing.T) {
	destination := startEchoServer(t)
	proxyListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(Config{
		HandshakeTimeout: time.Second,
		ConnectTimeout:   time.Second,
		IdleTimeout:      time.Second,
	}, &net.Dialer{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(ctx, proxyListener)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("Serve() error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Serve() did not shut down")
		}
	})

	client, err := net.Dial("tcp4", proxyListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tcpClient := client.(*net.TCPConn)
	defer tcpClient.Close()

	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	methodReply := make([]byte, 2)
	if _, err := io.ReadFull(client, methodReply); err != nil {
		t.Fatal(err)
	}
	if methodReply[0] != 5 || methodReply[1] != 0 {
		t.Fatalf("method reply = %v", methodReply)
	}

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
	request = append(request, portBytes(uint16(port))...)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	if code := readReplyCode(t, client); code != replySucceeded {
		t.Fatalf("CONNECT reply code = %d", code)
	}

	payload := []byte("hello through worker")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != string(payload) {
		t.Fatalf("relayed payload = %q", reply)
	}
	if err := tcpClient.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	for server.Stats().ActiveConnections != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	stats := server.Stats()
	if stats.ConnectionsTotal != 1 || stats.BytesFromClients != uint64(len(payload)) ||
		stats.BytesToClients != uint64(len(payload)) {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestServerRejectsUnsupportedCommandBeforeDial(t *testing.T) {
	dialer := &countingDialer{}
	server, err := NewServer(Config{
		HandshakeTimeout: time.Second,
		ConnectTimeout:   time.Second,
		IdleTimeout:      time.Second,
	}, dialer, nil)
	if err != nil {
		t.Fatal(err)
	}
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	done := make(chan error, 1)
	go func() {
		done <- server.ServeConn(context.Background(), serverSide)
	}()

	if _, err := clientSide.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(clientSide, method); err != nil {
		t.Fatal(err)
	}
	if _, err := clientSide.Write([]byte{5, commandUDPAssociate, 0, addressIPv4}); err != nil {
		t.Fatal(err)
	}
	if code := readReplyCode(t, clientSide); code != replyCommandNotSupported {
		t.Fatalf("reply code = %d", code)
	}
	if err := <-done; !errors.Is(err, errUnsupportedCommand) {
		t.Fatalf("ServeConn() error = %v", err)
	}
	if dialer.calls != 0 {
		t.Fatalf("dialer called %d times", dialer.calls)
	}
}

func TestServerCancellationClosesActiveSessions(t *testing.T) {
	proxyListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dialer := &pipeDialer{}
	server, err := NewServer(Config{
		HandshakeTimeout: time.Second,
		ConnectTimeout:   time.Second,
		IdleTimeout:      time.Minute,
	}, dialer, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, proxyListener) }()

	client, err := net.Dial("tcp4", proxyListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, _ = client.Write([]byte{5, 1, 0})
	_, _ = io.ReadFull(client, make([]byte, 2))
	request := []byte{5, 1, 0, 1, 192, 0, 2, 1, 0, 80}
	_, _ = client.Write(request)
	if code := readReplyCode(t, client); code != replySucceeded {
		t.Fatalf("reply code = %d", code)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not stop after cancellation")
	}
	if server.Stats().ActiveConnections != 0 {
		t.Fatalf("active connections = %d", server.Stats().ActiveConnections)
	}
}

func TestServerBacksOffAfterTemporaryAcceptFailure(t *testing.T) {
	server, err := NewServer(Config{
		HandshakeTimeout: time.Second,
		ConnectTimeout:   time.Second,
		IdleTimeout:      time.Second,
	}, &net.Dialer{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	listener := &acceptErrorListener{errors: []error{
		temporaryAcceptError{},
		errors.New("permanent accept failure"),
	}}
	started := time.Now()
	err = server.Serve(context.Background(), listener)
	if err == nil || err.Error() != "permanent accept failure" {
		t.Fatalf("Serve() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed < 5*time.Millisecond {
		t.Fatalf("temporary accept retry spun without backoff: %v", elapsed)
	}
}

func readReplyCode(t *testing.T, reader io.Reader) byte {
	t.Helper()
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		t.Fatal(err)
	}
	addressLength := 0
	switch header[3] {
	case addressIPv4:
		addressLength = 4
	case addressIPv6:
		addressLength = 16
	case addressDomain:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			t.Fatal(err)
		}
		addressLength = int(length[0])
	default:
		t.Fatalf("unknown reply address type %d", header[3])
	}
	if _, err := io.CopyN(io.Discard, reader, int64(addressLength+2)); err != nil {
		t.Fatal(err)
	}
	return header[1]
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

type countingDialer struct {
	calls int
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

func (d *countingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.calls++
	return nil, errors.New("unexpected dial")
}

type pipeDialer struct {
	mu    sync.Mutex
	peers []net.Conn
}

func (d *pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	server, peer := net.Pipe()
	d.mu.Lock()
	d.peers = append(d.peers, peer)
	d.mu.Unlock()
	return server, nil
}

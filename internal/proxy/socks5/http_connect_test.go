package socks5

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHTTPConnectDialer(t *testing.T) {
	tests := []struct {
		name       string
		response   string
		wantStatus int
	}{
		{
			name:     "success",
			response: "HTTP/1.1 200 Connection established\r\n\r\nhello",
		},
		{
			name:       "proxy refusal",
			response:   "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
			wantStatus: http.StatusForbidden,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proxyAddress, requests, stop := startHTTPConnectProxy(t, func(connection net.Conn) {
				_, _ = io.WriteString(connection, test.response)
			})
			defer stop()
			dialer := HTTPConnectDialer{
				ProxyAddress:     proxyAddress,
				NetDialer:        &net.Dialer{},
				HandshakeTimeout: time.Second,
			}
			connection, err := dialer.DialContext(
				context.Background(),
				"tcp",
				"ifconfig.me:443",
			)
			if test.wantStatus != 0 {
				var connectErr *HTTPConnectError
				if !errors.As(err, &connectErr) || connectErr.StatusCode != test.wantStatus {
					t.Fatalf("DialContext() error = %#v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("DialContext() error = %v", err)
				}
				defer connection.Close()
				payload := make([]byte, 5)
				if _, err := io.ReadFull(connection, payload); err != nil {
					t.Fatal(err)
				}
				if string(payload) != "hello" {
					t.Fatalf("tunnel payload = %q", payload)
				}
			}
			request := <-requests
			if request.Method != http.MethodConnect ||
				request.Host != "ifconfig.me:443" {
				t.Fatalf("CONNECT request = %s %s", request.Method, request.Host)
			}
		})
	}
}

func TestHTTPConnectDialerTimesOut(t *testing.T) {
	proxyAddress, _, stop := startHTTPConnectProxy(t, func(net.Conn) {
		time.Sleep(250 * time.Millisecond)
	})
	defer stop()
	dialer := HTTPConnectDialer{
		ProxyAddress:     proxyAddress,
		NetDialer:        &net.Dialer{},
		HandshakeTimeout: 25 * time.Millisecond,
	}
	_, err := dialer.DialContext(context.Background(), "tcp", "ifconfig.me:443")
	var networkErr net.Error
	if !errors.As(err, &networkErr) || !networkErr.Timeout() {
		t.Fatalf("DialContext() error = %#v, want timeout", err)
	}
}

func TestHTTPConnectDialerRejectsMalformedTarget(t *testing.T) {
	dialer := HTTPConnectDialer{
		ProxyAddress:     "192.0.2.1:3128",
		NetDialer:        &net.Dialer{},
		HandshakeTimeout: time.Second,
	}
	_, err := dialer.DialContext(
		context.Background(),
		"tcp",
		"example.com:443\r\nInjected: yes",
	)
	if err == nil || !strings.Contains(err.Error(), "invalid HTTP CONNECT target") {
		t.Fatalf("DialContext() error = %v", err)
	}
}

func TestBufferedConnForwardsTCPHalfClose(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	underlying := &recordingHalfCloser{Conn: left}
	connection := &bufferedConn{Conn: underlying, reader: left}
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := connection.CloseRead(); err != nil {
		t.Fatal(err)
	}
	if !underlying.writeClosed || !underlying.readClosed {
		t.Fatalf("half-close state = read:%t write:%t", underlying.readClosed, underlying.writeClosed)
	}
}

type recordingHalfCloser struct {
	net.Conn
	readClosed  bool
	writeClosed bool
}

func (c *recordingHalfCloser) CloseRead() error {
	c.readClosed = true
	return nil
}

func (c *recordingHalfCloser) CloseWrite() error {
	c.writeClosed = true
	return nil
}

func startHTTPConnectProxy(
	t *testing.T,
	respond func(net.Conn),
) (string, <-chan *http.Request, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan *http.Request, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		request, readErr := http.ReadRequest(bufio.NewReader(connection))
		if readErr != nil {
			return
		}
		requests <- request
		respond(connection)
	}()
	return listener.Addr().String(), requests, func() {
		_ = listener.Close()
		<-done
	}
}

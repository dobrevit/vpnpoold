package socks5

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxHTTPConnectResponseHeader = 32 * 1024

type HTTPConnectDialer struct {
	ProxyAddress     string
	NetDialer        Dialer
	HandshakeTimeout time.Duration
}

type HTTPConnectError struct {
	StatusCode int
}

func (e *HTTPConnectError) Error() string {
	return fmt.Sprintf("upstream HTTP proxy rejected CONNECT with status %d", e.StatusCode)
}

func (d HTTPConnectDialer) DialContext(
	ctx context.Context,
	network string,
	target string,
) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("HTTP CONNECT dialer supports TCP only")
	}
	if d.NetDialer == nil {
		return nil, errors.New("network dialer is required")
	}
	if d.HandshakeTimeout <= 0 {
		return nil, errors.New("HTTP CONNECT handshake timeout must be positive")
	}
	if err := validateConnectAuthority(d.ProxyAddress); err != nil {
		return nil, fmt.Errorf("invalid upstream HTTP proxy address: %w", err)
	}
	if err := validateConnectAuthority(target); err != nil {
		return nil, fmt.Errorf("invalid HTTP CONNECT target: %w", err)
	}

	connection, err := d.NetDialer.DialContext(ctx, "tcp", d.ProxyAddress)
	if err != nil {
		return nil, fmt.Errorf("connect to upstream HTTP proxy: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = connection.Close()
		}
	}()

	deadline := time.Now().Add(d.HandshakeTimeout)
	if contextDeadline, exists := ctx.Deadline(); exists && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(
		connection,
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		target,
		target,
	); err != nil {
		return nil, fmt.Errorf("write upstream HTTP CONNECT request: %w", err)
	}

	reader := bufio.NewReader(connection)
	header, err := readHTTPConnectResponseHeader(reader)
	if err != nil {
		return nil, err
	}
	response, err := http.ReadResponse(
		bufio.NewReader(bytes.NewReader(header)),
		&http.Request{Method: http.MethodConnect},
	)
	if err != nil {
		return nil, fmt.Errorf("parse upstream HTTP CONNECT response: %w", err)
	}
	_ = response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, &HTTPConnectError{StatusCode: response.StatusCode}
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	ok = true
	return &bufferedConn{Conn: connection, reader: reader}, nil
}

func validateConnectAuthority(authority string) error {
	host, portText, err := net.SplitHostPort(authority)
	if err != nil || host == "" || strings.ContainsAny(host, "\r\n") {
		return errors.New("address must contain a host and port")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

func readHTTPConnectResponseHeader(reader *bufio.Reader) ([]byte, error) {
	header := make([]byte, 0, 512)
	for len(header) <= maxHTTPConnectResponseHeader {
		value, err := reader.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("read upstream HTTP CONNECT response: %w", err)
		}
		header = append(header, value)
		if len(header) >= 4 && bytes.Equal(header[len(header)-4:], []byte("\r\n\r\n")) {
			return header, nil
		}
	}
	return nil, fmt.Errorf(
		"upstream HTTP CONNECT response header exceeds %d bytes",
		maxHTTPConnectResponseHeader,
	)
}

type bufferedConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedConn) Read(data []byte) (int, error) {
	return c.reader.Read(data)
}

func (c *bufferedConn) CloseWrite() error {
	connection, ok := c.Conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.ErrUnsupported
	}
	return connection.CloseWrite()
}

func (c *bufferedConn) CloseRead() error {
	connection, ok := c.Conn.(interface{ CloseRead() error })
	if !ok {
		return errors.ErrUnsupported
	}
	return connection.CloseRead()
}

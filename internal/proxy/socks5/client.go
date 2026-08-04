package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// ClientDialer establishes each requested TCP connection through one SOCKS5
// worker. It intentionally offers only the no-authentication method because
// worker listeners are protected by namespace firewall rules; client
// authentication belongs at the host dispatcher.
type ClientDialer struct {
	ProxyAddress     string
	NetDialer        Dialer
	HandshakeTimeout time.Duration
}

type ReplyError struct {
	Code byte
}

func (e *ReplyError) Error() string {
	return fmt.Sprintf("SOCKS5 worker CONNECT failed with reply code %d", e.Code)
}

func (d ClientDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("SOCKS5 dialer supports TCP only")
	}
	if d.NetDialer == nil {
		return nil, errors.New("network dialer is required")
	}
	if d.HandshakeTimeout <= 0 {
		return nil, errors.New("SOCKS5 handshake timeout must be positive")
	}
	if _, _, err := net.SplitHostPort(d.ProxyAddress); err != nil {
		return nil, fmt.Errorf("invalid SOCKS5 proxy address: %w", err)
	}

	connection, err := d.NetDialer.DialContext(ctx, "tcp", d.ProxyAddress)
	if err != nil {
		return nil, fmt.Errorf("connect to SOCKS5 worker: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = connection.Close()
		}
	}()
	if err := connection.SetDeadline(time.Now().Add(d.HandshakeTimeout)); err != nil {
		return nil, err
	}
	if _, err := connection.Write([]byte{version5, 1, methodNoAuthentication}); err != nil {
		return nil, fmt.Errorf("write SOCKS5 greeting: %w", err)
	}
	var methodReply [2]byte
	if _, err := io.ReadFull(connection, methodReply[:]); err != nil {
		return nil, fmt.Errorf("read SOCKS5 greeting reply: %w", err)
	}
	if methodReply != [2]byte{version5, methodNoAuthentication} {
		return nil, fmt.Errorf("SOCKS5 worker rejected authentication method")
	}

	request, err := connectRequest(target)
	if err != nil {
		return nil, err
	}
	if _, err := connection.Write(request); err != nil {
		return nil, fmt.Errorf("write SOCKS5 CONNECT request: %w", err)
	}
	replyCode, err := readConnectReply(connection)
	if err != nil {
		return nil, err
	}
	if replyCode != replySucceeded {
		return nil, &ReplyError{Code: replyCode}
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ok = true
	return connection, nil
}

func connectRequest(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target address: %w", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("target port must be between 1 and 65535")
	}
	request := []byte{version5, commandConnect, 0}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		if address.Is4() {
			raw := address.As4()
			request = append(request, addressIPv4)
			request = append(request, raw[:]...)
		} else {
			raw := address.As16()
			request = append(request, addressIPv6)
			request = append(request, raw[:]...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 || !validDomainBytes([]byte(host)) {
			return nil, errors.New("target domain is invalid")
		}
		request = append(request, addressDomain, byte(len(host)))
		request = append(request, host...)
	}
	var rawPort [2]byte
	binary.BigEndian.PutUint16(rawPort[:], uint16(port))
	request = append(request, rawPort[:]...)
	return request, nil
}

func readConnectReply(reader io.Reader) (byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, fmt.Errorf("read SOCKS5 CONNECT reply: %w", err)
	}
	if header[0] != version5 || header[2] != 0 {
		return 0, errors.New("SOCKS5 worker returned a malformed CONNECT reply")
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
			return 0, fmt.Errorf("read SOCKS5 reply domain length: %w", err)
		}
		addressLength = int(length[0])
	default:
		return 0, errors.New("SOCKS5 worker returned an unknown address type")
	}
	if _, err := io.CopyN(io.Discard, reader, int64(addressLength+2)); err != nil {
		return 0, fmt.Errorf("read SOCKS5 reply address: %w", err)
	}
	return header[1], nil
}

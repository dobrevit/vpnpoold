package socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestNegotiate(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantReply []byte
		wantError error
	}{
		{
			name:      "no authentication among methods",
			input:     []byte{5, 2, 2, 0},
			wantReply: []byte{5, 0},
		},
		{
			name:      "no acceptable method",
			input:     []byte{5, 1, 2},
			wantReply: []byte{5, 0xff},
			wantError: errNoAcceptableMethod,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			err := negotiate(bytes.NewReader(test.input), &output)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("negotiate() error = %v, want %v", err, test.wantError)
			}
			if !bytes.Equal(output.Bytes(), test.wantReply) {
				t.Fatalf("reply = %v, want %v", output.Bytes(), test.wantReply)
			}
		})
	}
}

func TestReadRequest(t *testing.T) {
	ipv4 := append([]byte{5, 1, 0, 1, 192, 0, 2, 10}, portBytes(443)...)
	domain := append([]byte{5, 1, 0, 3, 11}, []byte("example.com")...)
	domain = append(domain, portBytes(80)...)
	ipv6Bytes := netip.MustParseAddr("2001:db8::1").As16()
	ipv6 := append([]byte{5, 1, 0, 4}, ipv6Bytes[:]...)
	ipv6 = append(ipv6, portBytes(8443)...)

	tests := []struct {
		name      string
		input     []byte
		allowIPv6 bool
		want      string
		wantCode  byte
		wantError error
	}{
		{name: "IPv4", input: ipv4, want: "192.0.2.10:443"},
		{name: "domain", input: domain, want: "example.com:80"},
		{name: "IPv6 enabled", input: ipv6, allowIPv6: true, want: "[2001:db8::1]:8443"},
		{name: "IPv6 disabled", input: ipv6, wantCode: replyAddressTypeUnsupported, wantError: errIPv6Disabled},
		{
			name:      "UDP unsupported",
			input:     []byte{5, commandUDPAssociate, 0, 1},
			wantCode:  replyCommandNotSupported,
			wantError: errUnsupportedCommand,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, code, err := readRequest(bytes.NewReader(test.input), test.allowIPv6)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("readRequest() error = %v, want %v", err, test.wantError)
			}
			if test.wantError != nil {
				if code != test.wantCode {
					t.Fatalf("reply code = %d, want %d", code, test.wantCode)
				}
				return
			}
			if request.address() != test.want {
				t.Fatalf("address = %q, want %q", request.address(), test.want)
			}
		})
	}
}

func TestWriteReply(t *testing.T) {
	var output bytes.Buffer
	address := &net.TCPAddr{IP: net.ParseIP("192.0.2.5"), Port: 4321}
	if err := writeReply(&output, replySucceeded, address); err != nil {
		t.Fatal(err)
	}
	want := append([]byte{5, 0, 0, 1, 192, 0, 2, 5}, portBytes(4321)...)
	if !bytes.Equal(output.Bytes(), want) {
		t.Fatalf("reply = %v, want %v", output.Bytes(), want)
	}
}

func portBytes(port uint16) []byte {
	result := make([]byte, 2)
	binary.BigEndian.PutUint16(result, port)
	return result
}

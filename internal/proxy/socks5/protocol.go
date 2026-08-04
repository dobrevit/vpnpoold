package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
)

const (
	version5 = 0x05

	methodNoAuthentication = 0x00
	methodUsernamePassword = 0x02
	methodNoAcceptable     = 0xff

	commandConnect      = 0x01
	commandBind         = 0x02
	commandUDPAssociate = 0x03

	addressIPv4   = 0x01
	addressDomain = 0x03
	addressIPv6   = 0x04

	replySucceeded              = 0x00
	replyGeneralFailure         = 0x01
	replyNetworkUnreachable     = 0x03
	replyHostUnreachable        = 0x04
	replyConnectionRefused      = 0x05
	replyCommandNotSupported    = 0x07
	replyAddressTypeUnsupported = 0x08
)

const (
	MethodNoAuthentication = methodNoAuthentication
	MethodUsernamePassword = methodUsernamePassword
	MethodNoAcceptable     = methodNoAcceptable

	ReplySucceeded              = replySucceeded
	ReplyGeneralFailure         = replyGeneralFailure
	ReplyNetworkUnreachable     = replyNetworkUnreachable
	ReplyHostUnreachable        = replyHostUnreachable
	ReplyConnectionRefused      = replyConnectionRefused
	ReplyCommandNotSupported    = replyCommandNotSupported
	ReplyAddressTypeUnsupported = replyAddressTypeUnsupported
)

var (
	errNoAcceptableMethod = errors.New("client does not offer unauthenticated SOCKS5")
	errUnsupportedCommand = errors.New("SOCKS5 command is unsupported")
	errIPv6Disabled       = errors.New("IPv6 destinations are disabled")
)

type request struct {
	command byte
	host    string
	port    uint16
	ipv6    bool
}

type ConnectRequest struct {
	Host string
	Port uint16
	IPv6 bool
}

func (r ConnectRequest) Address() string {
	return net.JoinHostPort(r.Host, strconv.Itoa(int(r.Port)))
}

func ReadMethods(reader io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, fmt.Errorf("read SOCKS5 greeting: %w", err)
	}
	if header[0] != version5 {
		return nil, fmt.Errorf("unsupported SOCKS version %d", header[0])
	}
	if header[1] == 0 {
		return nil, errors.New("SOCKS5 greeting contains no methods")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return nil, fmt.Errorf("read SOCKS5 methods: %w", err)
	}
	return methods, nil
}

func OffersMethod(methods []byte, required byte) bool {
	for _, method := range methods {
		if method == required {
			return true
		}
	}
	return false
}

func WriteMethodSelection(writer io.Writer, method byte) error {
	_, err := writer.Write([]byte{version5, method})
	return err
}

func negotiate(reader io.Reader, writer io.Writer) error {
	methods, err := ReadMethods(reader)
	if err != nil {
		return err
	}
	if OffersMethod(methods, methodNoAuthentication) {
		return WriteMethodSelection(writer, methodNoAuthentication)
	}
	_ = WriteMethodSelection(writer, methodNoAcceptable)
	return errNoAcceptableMethod
}

func ReadConnectRequest(reader io.Reader, allowIPv6 bool) (ConnectRequest, byte, error) {
	parsed, reply, err := readRequest(reader, allowIPv6)
	return ConnectRequest{
		Host: parsed.host,
		Port: parsed.port,
		IPv6: parsed.ipv6,
	}, reply, err
}

func WriteConnectReply(writer io.Writer, code byte, address net.Addr) error {
	return writeReply(writer, code, address)
}

func readRequest(reader io.Reader, allowIPv6 bool) (request, byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return request{}, replyGeneralFailure, fmt.Errorf("read SOCKS5 request: %w", err)
	}
	if header[0] != version5 {
		return request{}, replyGeneralFailure, fmt.Errorf("unsupported SOCKS version %d", header[0])
	}
	if header[2] != 0 {
		return request{}, replyGeneralFailure, errors.New("SOCKS5 reserved byte is nonzero")
	}
	if header[1] != commandConnect {
		return request{command: header[1]}, replyCommandNotSupported, errUnsupportedCommand
	}

	result := request{command: header[1]}
	switch header[3] {
	case addressIPv4:
		raw := make([]byte, 4)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return request{}, replyGeneralFailure, fmt.Errorf("read IPv4 destination: %w", err)
		}
		var value [4]byte
		copy(value[:], raw)
		result.host = netip.AddrFrom4(value).String()
	case addressIPv6:
		raw := make([]byte, 16)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return request{}, replyGeneralFailure, fmt.Errorf("read IPv6 destination: %w", err)
		}
		var value [16]byte
		copy(value[:], raw)
		result.host = netip.AddrFrom16(value).String()
		result.ipv6 = true
	case addressDomain:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return request{}, replyGeneralFailure, fmt.Errorf("read domain length: %w", err)
		}
		if length[0] == 0 {
			return request{}, replyHostUnreachable, errors.New("destination domain is empty")
		}
		raw := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, raw); err != nil {
			return request{}, replyGeneralFailure, fmt.Errorf("read destination domain: %w", err)
		}
		if !validDomainBytes(raw) {
			return request{}, replyHostUnreachable, errors.New("destination domain contains invalid bytes")
		}
		result.host = string(raw)
	default:
		return request{}, replyAddressTypeUnsupported, fmt.Errorf("unsupported address type %d", header[3])
	}

	var port [2]byte
	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return request{}, replyGeneralFailure, fmt.Errorf("read destination port: %w", err)
	}
	result.port = binary.BigEndian.Uint16(port[:])
	if result.port == 0 {
		return request{}, replyHostUnreachable, errors.New("destination port is zero")
	}
	if result.ipv6 && !allowIPv6 {
		return request{}, replyAddressTypeUnsupported, errIPv6Disabled
	}
	return result, replySucceeded, nil
}

func validDomainBytes(raw []byte) bool {
	for _, value := range raw {
		if value == 0 || value < 0x21 || value > 0x7e {
			return false
		}
	}
	return true
}

func (r request) address() string {
	return net.JoinHostPort(r.host, strconv.Itoa(int(r.port)))
}

func writeReply(writer io.Writer, code byte, address net.Addr) error {
	ip := netip.IPv4Unspecified()
	port := uint16(0)
	if tcpAddress, ok := address.(*net.TCPAddr); ok {
		if parsed, valid := netip.AddrFromSlice(tcpAddress.IP); valid {
			ip = parsed.Unmap()
		}
		if tcpAddress.Port >= 0 && tcpAddress.Port <= 65535 {
			port = uint16(tcpAddress.Port)
		}
	}

	var response []byte
	if ip.Is6() {
		raw := ip.As16()
		response = make([]byte, 4+len(raw)+2)
		response[3] = addressIPv6
		copy(response[4:], raw[:])
	} else {
		raw := ip.As4()
		response = make([]byte, 4+len(raw)+2)
		response[3] = addressIPv4
		copy(response[4:], raw[:])
	}
	response[0] = version5
	response[1] = code
	binary.BigEndian.PutUint16(response[len(response)-2:], port)
	_, err := writer.Write(response)
	return err
}

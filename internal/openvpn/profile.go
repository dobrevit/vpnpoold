package openvpn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

const maxProfileSize = 2 * 1024 * 1024

type ProfileReader interface {
	ReadProfile(path string, limit int64) ([]byte, error)
}

type OSProfileReader struct{}

func (OSProfileReader) ReadProfile(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("profile must be a regular file, not a symbolic link")
	}
	if before.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("profile must not be accessible by group or other users")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("profile must be a regular file")
	}
	after, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() ||
		!os.SameFile(before, info) || !os.SameFile(info, after) {
		return nil, errors.New("profile changed while opening")
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("profile exceeds %d-byte limit", limit)
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, err
	}
	return data, nil
}

type Remote struct {
	Host     string
	Port     uint16
	Protocol string
}

type ResolvedEndpoint struct {
	Address  netip.Addr
	Port     uint16
	Protocol string
}

type ResolvedRemote struct {
	Source    Remote
	Endpoints []ResolvedEndpoint
}

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type Inspector struct {
	Reader ProfileReader
}

var prohibitedProfileDirectives = map[string]struct{}{
	"auth-user-pass-verify": {},
	"client-connect":        {},
	"client-disconnect":     {},
	"cd":                    {},
	"chroot":                {},
	"config":                {},
	"daemon":                {},
	"down":                  {},
	"ipchange":              {},
	"iproute":               {},
	"learn-address":         {},
	"log":                   {},
	"log-append":            {},
	"pkcs11-providers":      {},
	"plugin":                {},
	"providers":             {},
	"route-pre-down":        {},
	"route-up":              {},
	"script-security":       {},
	"status":                {},
	"syslog":                {},
	"tls-crypt-v2-verify":   {},
	"tls-verify":            {},
	"up":                    {},
	"writepid":              {},
}

func (i Inspector) Remotes(path string) ([]Remote, error) {
	if i.Reader == nil {
		return nil, errors.New("profile reader is required")
	}
	data, err := i.Reader.ReadProfile(path, maxProfileSize)
	if err != nil {
		return nil, fmt.Errorf("read OpenVPN profile metadata: %w", err)
	}
	if len(data) > maxProfileSize {
		return nil, fmt.Errorf("OpenVPN profile exceeds %d-byte limit", maxProfileSize)
	}
	remotes, err := parseRemotes(data)
	if err != nil {
		return nil, err
	}
	if len(remotes) == 0 {
		return nil, errors.New("OpenVPN profile contains no remote directives")
	}
	return remotes, nil
}

func ResolveRemotes(ctx context.Context, resolver Resolver, remotes []Remote) ([]ResolvedEndpoint, error) {
	groups, err := ResolveRemoteGroups(ctx, resolver, remotes)
	if err != nil {
		return nil, err
	}
	var result []ResolvedEndpoint
	seen := make(map[ResolvedEndpoint]struct{})
	for _, group := range groups {
		for _, endpoint := range group.Endpoints {
			if _, exists := seen[endpoint]; !exists {
				seen[endpoint] = struct{}{}
				result = append(result, endpoint)
			}
		}
	}
	return result, nil
}

func ResolveRemoteGroups(
	ctx context.Context,
	resolver Resolver,
	remotes []Remote,
) ([]ResolvedRemote, error) {
	if resolver == nil {
		return nil, errors.New("resolver is required")
	}
	result := make([]ResolvedRemote, 0, len(remotes))
	for index, remote := range remotes {
		addresses, err := resolveHost(ctx, resolver, remote.Host)
		if err != nil {
			return nil, fmt.Errorf("resolve OpenVPN remote %d: %w", index, err)
		}
		group := ResolvedRemote{Source: remote}
		seen := make(map[ResolvedEndpoint]struct{})
		for _, address := range addresses {
			address = address.Unmap()
			if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
				return nil, fmt.Errorf("OpenVPN remote %d resolved to an unusable address", index)
			}
			endpoint := ResolvedEndpoint{
				Address:  address,
				Port:     remote.Port,
				Protocol: remote.Protocol,
			}
			if _, exists := seen[endpoint]; !exists {
				seen[endpoint] = struct{}{}
				group.Endpoints = append(group.Endpoints, endpoint)
			}
		}
		if len(group.Endpoints) == 0 {
			return nil, fmt.Errorf("OpenVPN remote %d resolved to no addresses", index)
		}
		result = append(result, group)
	}
	if len(result) == 0 {
		return nil, errors.New("OpenVPN remotes resolved to no addresses")
	}
	return result, nil
}

func resolveHost(ctx context.Context, resolver Resolver, host string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{address}, nil
	}
	addresses, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, errors.New("hostname has no IP addresses")
	}
	return addresses, nil
}

func parseRemotes(data []byte) ([]Remote, error) {
	lines := strings.Split(string(data), "\n")
	globalProtocol := "udp"
	type pendingRemote struct {
		fields []string
		line   int
		scope  int
	}
	var pending []pendingRemote
	connectionProtocols := make(map[int]string)
	inlineBlock := ""
	inConnection := false
	scope := 0
	nextScope := 1
	for lineNumber, line := range lines {
		trimmed := strings.TrimSpace(line)
		if inlineBlock != "" {
			if strings.EqualFold(trimmed, "</"+inlineBlock+">") {
				inlineBlock = ""
			}
			continue
		}
		if inConnection && strings.EqualFold(trimmed, "</connection>") {
			inConnection = false
			scope = 0
			continue
		}
		if name, ok := openingInlineBlock(trimmed); ok {
			if name == "connection" {
				if inConnection {
					return nil, fmt.Errorf("OpenVPN connection block on line %d is nested", lineNumber+1)
				}
				inConnection = true
				scope = nextScope
				nextScope++
				continue
			}
			inlineBlock = name
			continue
		}
		fields, err := splitDirective(trimmed)
		if err != nil {
			return nil, fmt.Errorf("parse OpenVPN directive on line %d: invalid quoting", lineNumber+1)
		}
		if len(fields) == 0 {
			continue
		}
		directive := strings.TrimPrefix(strings.ToLower(fields[0]), "--")
		if _, prohibited := prohibitedProfileDirectives[directive]; prohibited {
			return nil, fmt.Errorf(
				"OpenVPN directive %s on line %d is prohibited in supervised client profiles",
				directive,
				lineNumber+1,
			)
		}
		switch directive {
		case "proto":
			if len(fields) != 2 {
				return nil, fmt.Errorf("OpenVPN directive proto on line %d has invalid arguments", lineNumber+1)
			}
			normalized, normalizeErr := normalizeProtocol(fields[1])
			err = normalizeErr
			if err != nil {
				return nil, fmt.Errorf("OpenVPN directive proto on line %d is unsupported", lineNumber+1)
			}
			if inConnection {
				connectionProtocols[scope] = normalized
			} else {
				globalProtocol = normalized
			}
		case "remote":
			pending = append(pending, pendingRemote{
				fields: append([]string(nil), fields...), line: lineNumber + 1, scope: scope,
			})
		}
	}
	if inlineBlock != "" {
		return nil, errors.New("OpenVPN profile contains an unterminated inline block")
	}
	if inConnection {
		return nil, errors.New("OpenVPN profile contains an unterminated connection block")
	}
	remotes := make([]Remote, 0, len(pending))
	for _, item := range pending {
		protocol := globalProtocol
		if connectionProtocol, exists := connectionProtocols[item.scope]; exists {
			protocol = connectionProtocol
		}
		remote, err := parseRemote(item.fields, protocol)
		if err != nil {
			return nil, fmt.Errorf("OpenVPN directive remote on line %d is invalid", item.line)
		}
		remotes = append(remotes, remote)
	}
	return remotes, nil
}

func parseRemote(fields []string, defaultProtocol string) (Remote, error) {
	if len(fields) < 2 || len(fields) > 4 || fields[1] == "" || strings.HasPrefix(fields[1], "-") {
		return Remote{}, errors.New("invalid remote arguments")
	}
	result := Remote{Host: fields[1], Port: 1194, Protocol: defaultProtocol}
	var err error
	if len(fields) >= 3 {
		port, parseErr := strconv.ParseUint(fields[2], 10, 16)
		if parseErr != nil || port == 0 {
			return Remote{}, errors.New("invalid port")
		}
		result.Port = uint16(port)
	}
	if len(fields) == 4 {
		result.Protocol, err = normalizeProtocol(fields[3])
		if err != nil {
			return Remote{}, err
		}
	}
	return result, nil
}

func normalizeProtocol(value string) (string, error) {
	switch strings.ToLower(value) {
	case "udp", "udp4", "udp6":
		return "udp", nil
	case "tcp", "tcp4", "tcp6", "tcp-client", "tcp4-client", "tcp6-client":
		return "tcp", nil
	default:
		return "", errors.New("unsupported protocol")
	}
}

func openingInlineBlock(line string) (string, bool) {
	if len(line) < 3 || line[0] != '<' || line[len(line)-1] != '>' || strings.HasPrefix(line, "</") {
		return "", false
	}
	name := strings.TrimSpace(line[1 : len(line)-1])
	if name == "" || strings.ContainsAny(name, " \t<>") {
		return "", false
	}
	return strings.ToLower(name), true
}

func splitDirective(line string) ([]string, error) {
	var fields []string
	var current strings.Builder
	var quote rune
	escaped := false
	tokenStarted := false
	for _, value := range line {
		if escaped {
			current.WriteRune(value)
			tokenStarted = true
			escaped = false
			continue
		}
		if value == '\\' {
			escaped = true
			tokenStarted = true
			continue
		}
		if quote != 0 {
			if value == quote {
				quote = 0
			} else {
				current.WriteRune(value)
			}
			tokenStarted = true
			continue
		}
		if value == '\'' || value == '"' {
			quote = value
			tokenStarted = true
			continue
		}
		if value == '#' || value == ';' {
			if !tokenStarted {
				break
			}
			current.WriteRune(value)
			continue
		}
		if value == ' ' || value == '\t' || value == '\r' {
			if tokenStarted {
				fields = append(fields, current.String())
				current.Reset()
				tokenStarted = false
			}
			continue
		}
		current.WriteRune(value)
		tokenStarted = true
	}
	if escaped || quote != 0 {
		return nil, errors.New("invalid quoting")
	}
	if tokenStarted {
		fields = append(fields, current.String())
	}
	return fields, nil
}

var _ Resolver = (*net.Resolver)(nil)

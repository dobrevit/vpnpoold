package namespace

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	ipForwardPath   = "/proc/sys/net/ipv4/ip_forward"
	allRPFilterPath = "/proc/sys/net/ipv4/conf/all/rp_filter"
)

type FileReader interface {
	ReadFile(string) ([]byte, error)
}

type OSFileReader struct{}

func (OSFileReader) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

type HostPrerequisites struct {
	IPv4Forwarding bool
	RPFilterMode   string
	Warnings       []string
}

func CheckHostPrerequisites(files FileReader) (HostPrerequisites, error) {
	if files == nil {
		return HostPrerequisites{}, errors.New("file reader is required")
	}
	forwarding, err := readSysctl(files, ipForwardPath)
	if err != nil {
		return HostPrerequisites{}, fmt.Errorf("read IPv4 forwarding state: %w", err)
	}
	rpFilter, err := readSysctl(files, allRPFilterPath)
	if err != nil {
		return HostPrerequisites{}, fmt.Errorf("read reverse-path filtering state: %w", err)
	}

	result := HostPrerequisites{
		IPv4Forwarding: forwarding == "1",
		RPFilterMode:   rpFilter,
	}
	if !result.IPv4Forwarding {
		return result, errors.New("net.ipv4.ip_forward must be 1")
	}
	switch rpFilter {
	case "0":
	case "1":
		result.Warnings = append(result.Warnings,
			"net.ipv4.conf.all.rp_filter is strict; validate per-veth routing before starting workers")
	case "2":
		result.Warnings = append(result.Warnings,
			"net.ipv4.conf.all.rp_filter is loose; namespace firewall remains the primary egress boundary")
	default:
		return result, fmt.Errorf("unexpected net.ipv4.conf.all.rp_filter value %q", rpFilter)
	}
	return result, nil
}

func readSysctl(files FileReader, path string) (string, error) {
	value, err := files.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(value)), nil
}

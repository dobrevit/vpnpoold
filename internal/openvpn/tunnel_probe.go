package openvpn

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/dobrevit/vpnpoold/internal/netutil"
	"github.com/dobrevit/vpnpoold/internal/process"
)

type LinuxTunnelProbe struct {
	Runner          process.Runner
	IPBinary        string
	Namespace       string
	TunnelInterface string
	RoutePrefix     string
}

func (p LinuxTunnelProbe) Check(ctx context.Context) error {
	if err := p.validate(); err != nil {
		return err
	}
	link, err := p.Runner.Run(ctx, process.Command{
		Path: p.IPBinary,
		Args: []string{"-n", p.Namespace, "-o", "link", "show", "dev", p.TunnelInterface},
	})
	if err != nil {
		return fmt.Errorf("inspect tunnel interface: %w", err)
	}
	if !linkFlagsContainUp(link.Stdout) {
		return errors.New("tunnel interface is not up")
	}

	routePrefix := p.RoutePrefix
	route, err := p.Runner.Run(ctx, process.Command{
		Path: p.IPBinary,
		Args: []string{"-n", p.Namespace, "route", "show", "dev", p.TunnelInterface},
	})
	if err != nil {
		return fmt.Errorf("inspect VPN route: %w", err)
	}
	if !vpnRoutePresent(route.Stdout, routePrefix) {
		return errors.New("VPN route through tunnel interface is missing")
	}
	return nil
}

func (p LinuxTunnelProbe) validate() error {
	if p.Runner == nil {
		return errors.New("process runner is required")
	}
	if !filepath.IsAbs(p.IPBinary) {
		return errors.New("ip binary path must be absolute")
	}
	if !netutil.IsValidNamespaceName(p.Namespace) ||
		!netutil.IsValidInterfaceName(p.TunnelInterface) {
		return errors.New("namespace or tunnel interface name is invalid")
	}
	if p.RoutePrefix != "" && p.RoutePrefix != "default" {
		prefix, err := netip.ParsePrefix(p.RoutePrefix)
		if err != nil || prefix.String() != p.RoutePrefix {
			return errors.New("route prefix must be default or a canonical IP prefix")
		}
	}
	return nil
}

func vpnRoutePresent(output, routePrefix string) bool {
	if routePrefix != "" {
		for _, line := range strings.Split(output, "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == routePrefix {
				return true
			}
		}
		return false
	}

	hasLowerHalf := false
	hasUpperHalf := false
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "default":
			return true
		case "0.0.0.0/1":
			hasLowerHalf = true
		case "128.0.0.0/1":
			hasUpperHalf = true
		}
	}
	return hasLowerHalf && hasUpperHalf
}

func linkFlagsContainUp(output string) bool {
	start := strings.IndexByte(output, '<')
	end := strings.IndexByte(output, '>')
	if start < 0 || end <= start {
		return false
	}
	for _, flag := range strings.Split(output[start+1:end], ",") {
		if flag == "UP" {
			return true
		}
	}
	return false
}

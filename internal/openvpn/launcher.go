package openvpn

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/dobrevit/vpnpoold/internal/netutil"
	"github.com/dobrevit/vpnpoold/internal/process"
)

type LaunchSpec struct {
	Namespace         string
	ProfilePath       string
	WorkingDirectory  string
	TunnelInterface   string
	ManagementSocket  string
	AuthRetryInteract bool
}

type Launcher struct {
	Starter       process.Starter
	IPBinary      string
	OpenVPNBinary string
}

func (l Launcher) Start(ctx context.Context, spec LaunchSpec) (process.ManagedProcess, error) {
	if err := l.validate(spec); err != nil {
		return nil, err
	}
	command := process.Command{
		Path: l.IPBinary,
		Env:  []string{"LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"},
		Args: []string{
			"netns", "exec", spec.Namespace,
			l.OpenVPNBinary,
			"--cd", spec.WorkingDirectory,
			"--config", spec.ProfilePath,
			"--dev", spec.TunnelInterface,
			"--management", spec.ManagementSocket, "unix",
			"--management-hold",
			"--management-query-passwords",
			"--management-forget-disconnect",
			"--auth-nocache",
			"--script-security", "1",
		},
	}
	if spec.AuthRetryInteract {
		command.Args = append(command.Args, "--auth-retry", "interact")
	}
	running, err := l.Starter.Start(ctx, command)
	if err != nil {
		return nil, fmt.Errorf("start OpenVPN in namespace %q: %w", spec.Namespace, err)
	}
	return running, nil
}

func (l Launcher) validate(spec LaunchSpec) error {
	if l.Starter == nil {
		return errors.New("process starter is required")
	}
	if !filepath.IsAbs(l.IPBinary) || !filepath.IsAbs(l.OpenVPNBinary) {
		return errors.New("ip and OpenVPN binary paths must be absolute")
	}
	if !netutil.IsValidNamespaceName(spec.Namespace) {
		return errors.New("namespace name is invalid")
	}
	if !filepath.IsAbs(spec.ProfilePath) || filepath.Ext(spec.ProfilePath) != ".ovpn" {
		return errors.New("profile path must be an absolute .ovpn path")
	}
	if !filepath.IsAbs(spec.WorkingDirectory) {
		return errors.New("profile working directory must be absolute")
	}
	if !netutil.IsValidInterfaceName(spec.TunnelInterface) {
		return errors.New("tunnel interface name is invalid")
	}
	if !filepath.IsAbs(spec.ManagementSocket) {
		return errors.New("management socket path must be absolute")
	}
	return nil
}

package openvpn

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/dobrevit/vpnpoold/internal/process"
)

func TestLauncherUsesDirectNamespaceCommand(t *testing.T) {
	starter := &recordingStarter{process: fakeProcess{}}
	launcher := Launcher{
		Starter:       starter,
		IPBinary:      "/usr/sbin/ip",
		OpenVPNBinary: "/usr/sbin/openvpn",
	}
	spec := LaunchSpec{
		Namespace:        "vpnpool-1234567890",
		ProfilePath:      "/etc/vpnpoold/profiles/france.ovpn",
		WorkingDirectory: "/etc/vpnpoold/profiles",
		TunnelInterface:  "tun0",
		ManagementSocket: "/run/vpnpoold/france.management.sock",
	}
	if _, err := launcher.Start(context.Background(), spec); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	want := process.Command{
		Path: "/usr/sbin/ip",
		Env:  []string{"LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"},
		Args: []string{
			"netns", "exec", "vpnpool-1234567890",
			"/usr/sbin/openvpn",
			"--cd", "/etc/vpnpoold/profiles",
			"--config", "/etc/vpnpoold/profiles/france.ovpn",
			"--dev", "tun0",
			"--management", "/run/vpnpoold/france.management.sock", "unix",
			"--management-hold",
			"--management-query-passwords",
			"--management-forget-disconnect",
			"--auth-nocache",
			"--script-security", "1",
		},
	}
	if !reflect.DeepEqual(starter.command, want) {
		t.Fatalf("command = %#v, want %#v", starter.command, want)
	}
}

func TestLauncherRejectsInjectedNamespace(t *testing.T) {
	launcher := Launcher{
		Starter:       &recordingStarter{},
		IPBinary:      "/usr/sbin/ip",
		OpenVPNBinary: "/usr/sbin/openvpn",
	}
	_, err := launcher.Start(context.Background(), LaunchSpec{
		Namespace:        "vpn;reboot",
		ProfilePath:      "/profiles/test.ovpn",
		WorkingDirectory: "/profiles",
		TunnelInterface:  "tun0",
		ManagementSocket: "/run/test.sock",
	})
	if err == nil {
		t.Fatal("Start() unexpectedly accepted injected namespace")
	}
}

type recordingStarter struct {
	command process.Command
	process process.ManagedProcess
}

func (s *recordingStarter) Start(_ context.Context, command process.Command) (process.ManagedProcess, error) {
	s.command = command
	if s.process == nil {
		return nil, errors.New("not started")
	}
	return s.process, nil
}

type fakeProcess struct{}

func (fakeProcess) PID() int                 { return 123 }
func (fakeProcess) Wait() error              { return nil }
func (fakeProcess) Signal(_ os.Signal) error { return nil }
func (fakeProcess) Kill() error              { return nil }

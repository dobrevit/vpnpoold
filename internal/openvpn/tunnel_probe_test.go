package openvpn

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dobrevit/vpnpoold/internal/process"
)

func TestLinuxTunnelProbeRequiresUpInterfaceAndRoute(t *testing.T) {
	tests := []struct {
		name      string
		link      string
		route     string
		runError  error
		wantError string
	}{
		{
			name:  "ready",
			link:  "7: tun0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1500 state UNKNOWN\n",
			route: "default via 10.8.0.1 dev tun0\n",
		},
		{
			name: "def1 full tunnel",
			link: "7: tun0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1500 state UNKNOWN\n",
			route: "0.0.0.0/1 via 10.8.0.1 dev tun0\n" +
				"128.0.0.0/1 via 10.8.0.1 dev tun0\n",
		},
		{
			name:      "only half of def1 route",
			link:      "7: tun0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1500 state UNKNOWN\n",
			route:     "0.0.0.0/1 via 10.8.0.1 dev tun0\n",
			wantError: "missing",
		},
		{
			name:      "interface down",
			link:      "7: tun0: <POINTOPOINT,NOARP> mtu 1500 state DOWN\n",
			wantError: "not up",
		},
		{
			name:      "route missing",
			link:      "7: tun0: <POINTOPOINT,UP> mtu 1500 state UNKNOWN\n",
			wantError: "missing",
		},
		{
			name:      "command failure",
			runError:  errors.New("not found"),
			wantError: "inspect tunnel",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &probeRunner{link: test.link, route: test.route, err: test.runError}
			probe := LinuxTunnelProbe{
				Runner: runner, IPBinary: "/usr/sbin/ip",
				Namespace: "vpnpool-123", TunnelInterface: "tun0",
			}
			err := probe.Check(context.Background())
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("Check() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Check() error = %v", err)
			}
		})
	}
}

type probeRunner struct {
	link  string
	route string
	err   error
	calls int
}

func (r *probeRunner) Run(_ context.Context, _ process.Command) (process.Result, error) {
	r.calls++
	if r.err != nil {
		return process.Result{}, r.err
	}
	if r.calls == 1 {
		return process.Result{Stdout: r.link}, nil
	}
	return process.Result{Stdout: r.route}, nil
}

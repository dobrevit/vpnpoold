package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestNormalizeLegacyFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "single-dash long flags become double-dash",
			args: []string{"status", "-config", "/etc/vpnpoold/vpnpoold.yaml", "-format", "json"},
			want: []string{"status", "--config", "/etc/vpnpoold/vpnpoold.yaml", "--format", "json"},
		},
		{
			name: "inline values are preserved",
			args: []string{"status", "-format=json"},
			want: []string{"status", "--format=json"},
		},
		{
			name: "double-dash form is untouched",
			args: []string{"status", "--format", "json"},
			want: []string{"status", "--format", "json"},
		},
		{
			name: "shorthand flags are untouched",
			args: []string{"-h"},
			want: []string{"-h"},
		},
		{
			name: "everything after a bare double-dash is literal",
			args: []string{"worker", "enable", "--", "-config"},
			want: []string{"worker", "enable", "--", "-config"},
		},
		{
			name: "negative numbers and mixed case are not flags",
			args: []string{"status", "-5m", "-Format"},
			want: []string{"status", "-5m", "-Format"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := normalizeLegacyFlags(test.args)
			if strings.Join(got, " ") != strings.Join(test.want, " ") {
				t.Fatalf("normalizeLegacyFlags(%q) = %q, want %q", test.args, got, test.want)
			}
		})
	}
}

func TestEnvironmentSuppliesFlagValues(t *testing.T) {
	t.Setenv("VPNPOOLD_FORMAT", "json")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"go_version"`) {
		t.Fatalf("environment did not select JSON output: %q", stdout.String())
	}
}

func TestExplicitFlagOverridesEnvironment(t *testing.T) {
	t.Setenv("VPNPOOLD_FORMAT", "json")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version", "--format", "text"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "vpnpoold ") {
		t.Fatalf("explicit flag did not win over environment: %q", stdout.String())
	}
}

func TestInvalidEnvironmentValueIsAUsageError(t *testing.T) {
	t.Setenv("VPNPOOLD_TIMEOUT", "not-a-duration")
	var stdout, stderr bytes.Buffer
	code := run([]string{"status"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "VPNPOOLD_TIMEOUT") {
		t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
	}
}

// The daemon re-execs worker-proxy with a fixed argument vector and a minimal
// environment. Binding its flags to the ambient environment would let an
// operator's shell move a namespace worker's listener or widen the client it
// accepts, so worker-proxy must ignore VPNPOOLD_* entirely.
func TestWorkerProxyIgnoresAmbientEnvironment(t *testing.T) {
	t.Setenv("VPNPOOLD_LISTEN", "10.0.0.2:1081")
	t.Setenv("VPNPOOLD_ALLOWED_CLIENT", "10.0.0.1")
	t.Setenv("VPNPOOLD_WORKER_ID", "worker-1")
	var stdout, stderr bytes.Buffer
	code := run([]string{"worker-proxy"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "listen address") {
		t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
	}
}

func TestUnknownCommandExitsTwo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"bogus"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
	}
}

func TestWorkerRequiresAnAction(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"worker"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "enable, disable, drain, undrain, or restart") {
		t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
	}
}

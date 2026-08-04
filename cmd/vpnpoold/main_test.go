package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dobrevit/vpnpoold/internal/control"
)

func TestWriteStatusTable(t *testing.T) {
	var output bytes.Buffer
	writeStatusTable(&output, control.StatusResponse{
		Workers: []control.WorkerStatus{{
			ID:                "worker-1",
			Enabled:           true,
			State:             "HEALTHY",
			Available:         true,
			ActiveConnections: 2,
			OpenVPNRestarts:   1,
			ProxyRestarts:     3,
			PublicIP:          "203.0.113.10",
		}, {
			ID:      "worker-2",
			Enabled: false,
			State:   "DISABLED",
		}},
	})
	text := output.String()
	for _, expected := range []string{
		"WORKER", "ENABLED", "STATE", "AVAILABLE", "ACTIVE",
		"VPN RESTARTS", "PROXY RESTARTS", "PUBLIC IP",
		"worker-1", "true", "HEALTHY", "203.0.113.10",
		"worker-2", "false", "DISABLED", "-",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("status table missing %q:\n%s", expected, text)
		}
	}
}

func TestAbsoluteExecutableRejectsWritableBinaryAndDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "test-tool")
	if err := os.WriteFile(path, []byte("test"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	resolved, err := absoluteExecutable("test-tool")
	if err != nil || resolved != path {
		t.Fatalf("absoluteExecutable() = %q, %v", resolved, err)
	}
	if err := os.Chmod(path, 0o720); err != nil {
		t.Fatal(err)
	}
	if _, err := absoluteExecutable("test-tool"); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("writable executable error = %v", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := absoluteExecutable("test-tool"); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("writable directory error = %v", err)
	}
}

func TestRunRejectsUnsupportedStatusFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := run(
		[]string{"status", "-format", "yaml"},
		&stdout,
		&stderr,
	)
	if exitCode != 2 || !strings.Contains(stderr.String(), "table or json") {
		t.Fatalf("run() = %d, stderr = %q", exitCode, stderr.String())
	}
}

func TestRunVersionJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := run(
		[]string{"version", "-format", "json"},
		&stdout,
		&stderr,
	)
	if exitCode != 0 ||
		!strings.Contains(stdout.String(), `"version":"dev"`) ||
		stderr.Len() != 0 {
		t.Fatalf(
			"run() = %d, stdout = %q, stderr = %q",
			exitCode,
			stdout.String(),
			stderr.String(),
		)
	}
}

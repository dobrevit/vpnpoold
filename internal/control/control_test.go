package control

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dobrevit/vpnpoold/internal/proxy/dispatcher"
	"github.com/dobrevit/vpnpoold/internal/worker"
)

func TestStatusRoundTripAndPrivateSocket(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(directory, "control.sock")
	model, err := worker.NewModel("worker-1")
	if err != nil {
		t.Fatal(err)
	}
	actions := &recordingActions{}
	server, err := NewServerWithStats(socketPath, func() []worker.Snapshot {
		snapshot := model.Snapshot()
		snapshot.Evidence.PublicIP = netip.MustParseAddr("8.8.8.8")
		snapshot.Evidence.ExpectedIPConfigured = true
		snapshot.Evidence.ExpectedIPChecked = true
		snapshot.Evidence.ExpectedIPMatches = true
		snapshot.Evidence.UniquenessEnforced = true
		snapshot.Evidence.UniquenessChecked = true
		snapshot.Evidence.PublicIPUnique = true
		snapshot.ConnectionsTotal = 3
		snapshot.OpenVPNRestarts = 2
		return []worker.Snapshot{snapshot}
	}, func() dispatcher.Stats {
		return dispatcher.Stats{ConnectionsTotal: 4}
	}, actions, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := server.Listen()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket mode = %o, want 600", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()

	requestContext, requestCancel := context.WithTimeout(context.Background(), time.Second)
	status, err := Status(requestContext, socketPath)
	requestCancel()
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if len(status.Workers) != 1 || status.Workers[0].ID != "worker-1" ||
		status.Workers[0].State != "DISABLED" ||
		status.Workers[0].PublicIP != "8.8.8.8" ||
		!status.Workers[0].ExpectedIPConfigured ||
		!status.Workers[0].ExpectedIPVerified ||
		!status.Workers[0].UniquenessEnforced ||
		!status.Workers[0].PublicIPUnique ||
		status.Workers[0].ConnectionsTotal != 3 ||
		status.Workers[0].OpenVPNRestarts != 2 ||
		status.Dispatcher.ConnectionsTotal != 4 {
		t.Fatalf("status = %+v", status)
	}
	for _, operation := range []string{"enable", "disable", "drain", "undrain", "restart"} {
		actionContext, actionCancel := context.WithTimeout(context.Background(), time.Second)
		err := WorkerAction(actionContext, socketPath, operation, "worker-1")
		actionCancel()
		if err != nil {
			t.Fatalf("WorkerAction(%q) error = %v", operation, err)
		}
	}
	reloadContext, reloadCancel := context.WithTimeout(context.Background(), time.Second)
	if err := Reload(reloadContext, socketPath); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	reloadCancel()
	if got := actions.operations; len(got) != 6 ||
		got[0] != "enable:worker-1" ||
		got[1] != "disable:worker-1" ||
		got[2] != "drain:worker-1" ||
		got[3] != "undrain:worker-1" ||
		got[4] != "restart:worker-1" ||
		got[5] != "reload" {
		t.Fatalf("worker operations = %v", got)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("control socket was not removed: %v", err)
	}
}

type recordingActions struct {
	operations []string
}

func (a *recordingActions) SetWorkerEnabled(_ context.Context, workerID string, enabled bool) error {
	operation := "disable:"
	if enabled {
		operation = "enable:"
	}
	a.operations = append(a.operations, operation+workerID)
	return nil
}

func (a *recordingActions) SetWorkerDraining(_ context.Context, workerID string, draining bool) error {
	operation := "undrain:"
	if draining {
		operation = "drain:"
	}
	a.operations = append(a.operations, operation+workerID)
	return nil
}

func (a *recordingActions) RestartWorker(_ context.Context, workerID string) error {
	a.operations = append(a.operations, "restart:"+workerID)
	return nil
}

func (a *recordingActions) Reload(context.Context) error {
	a.operations = append(a.operations, "reload")
	return nil
}

func TestListenRefusesNonSocketPath(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(directory, "control.sock")
	if err := os.WriteFile(socketPath, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(socketPath, func() []worker.Snapshot { return nil }, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Listen(); err == nil {
		t.Fatal("Listen() unexpectedly replaced a regular file")
	}
}

func TestListenRefusesAccessibleSocketDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(
		filepath.Join(directory, "control.sock"),
		func() []worker.Snapshot { return nil },
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Listen(); err == nil || !strings.Contains(err.Error(), "accessible") {
		t.Fatalf("Listen() error = %v", err)
	}
}

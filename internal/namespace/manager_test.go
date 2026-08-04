package namespace

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/dobrevit/vpnpoold/internal/netutil"
	"github.com/dobrevit/vpnpoold/internal/process"
)

func TestManagerCreateUsesAuditableCommandSequence(t *testing.T) {
	runner := &recordingRunner{}
	manager, err := NewManager(runner, "/usr/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	allocation := testAllocation()
	if err := manager.Create(context.Background(), allocation); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	var args [][]string
	for _, command := range runner.commands {
		if command.Path != "/usr/sbin/ip" {
			t.Fatalf("unexpected command path %q", command.Path)
		}
		args = append(args, command.Args)
	}
	want := [][]string{
		{"netns", "list"},
		{"netns", "add", "vpnpool-1234567890"},
		{"link", "add", "vph1234567890", "type", "veth", "peer", "name", "vpn1234567890"},
		{"link", "set", "vpn1234567890", "netns", "vpnpool-1234567890"},
		{"addr", "add", "10.231.0.1/30", "dev", "vph1234567890"},
		{"link", "set", "dev", "vph1234567890", "up"},
		{"-n", "vpnpool-1234567890", "link", "set", "dev", "lo", "up"},
		{"-n", "vpnpool-1234567890", "addr", "add", "10.231.0.2/30", "dev", "vpn1234567890"},
		{"-n", "vpnpool-1234567890", "link", "set", "dev", "vpn1234567890", "up"},
		{"-n", "vpnpool-1234567890", "route", "add", "default", "via", "10.231.0.1", "dev", "vpn1234567890"},
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("command args:\n got: %#v\nwant: %#v", args, want)
	}
}

func TestManagerCreateRollsBackOnFailure(t *testing.T) {
	runner := &recordingRunner{failContaining: "addr add"}
	manager, err := NewManager(runner, "/usr/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	err = manager.Create(context.Background(), testAllocation())
	if err == nil || !strings.Contains(err.Error(), "assign host veth address") {
		t.Fatalf("Create() error = %v", err)
	}
	if !runner.sawArgs("netns delete vpnpool-1234567890") {
		t.Fatalf("rollback did not delete namespace: %#v", runner.commands)
	}
}

func TestManagerDeleteIsIdempotent(t *testing.T) {
	runner := &recordingRunner{}
	manager, err := NewManager(runner, "/usr/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Delete(context.Background(), testAllocation()); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if runner.sawArgs("netns delete") || runner.sawArgs("link delete") {
		t.Fatalf("Delete issued mutation for absent resources: %#v", runner.commands)
	}
}

func TestManagerDeleteAcceptsVethDisappearingAfterExistenceCheck(t *testing.T) {
	runner := &recordingRunner{
		linkList:           "7: vph1234567890@if8: <BROADCAST,UP> mtu 1500\n",
		linkVanishOnDelete: true,
	}
	manager, err := NewManager(runner, "/usr/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Delete(context.Background(), testAllocation()); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if !runner.sawArgs("link delete vph1234567890") {
		t.Fatal("Delete did not attempt to remove the observed veth")
	}
}

func TestManagerRefusesExistingNamespace(t *testing.T) {
	runner := &recordingRunner{namespaceList: "vpnpool-1234567890 (id: 4)\n"}
	manager, err := NewManager(runner, "/usr/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	err = manager.Create(context.Background(), testAllocation())
	if err == nil || !strings.Contains(err.Error(), "stale resources") {
		t.Fatalf("Create() error = %v", err)
	}
}

type recordingRunner struct {
	commands           []process.Command
	namespaceList      string
	linkList           string
	failContaining     string
	linkVanishOnDelete bool
}

func (r *recordingRunner) Run(_ context.Context, command process.Command) (process.Result, error) {
	r.commands = append(r.commands, command)
	joined := strings.Join(command.Args, " ")
	if r.failContaining != "" && strings.Contains(joined, r.failContaining) {
		r.failContaining = ""
		return process.Result{}, errors.New("injected failure")
	}
	if r.linkVanishOnDelete && joined == "link delete vph1234567890" {
		r.linkList = ""
		return process.Result{}, errors.New("link vanished")
	}
	switch joined {
	case "netns list":
		return process.Result{Stdout: r.namespaceList}, nil
	case "-o link show":
		return process.Result{Stdout: r.linkList}, nil
	default:
		if strings.HasPrefix(joined, "netns add ") {
			r.namespaceList = strings.TrimPrefix(joined, "netns add ") + "\n"
		}
		if strings.HasPrefix(joined, "netns delete ") {
			r.namespaceList = ""
		}
		return process.Result{}, nil
	}
}

func (r *recordingRunner) sawArgs(fragment string) bool {
	for _, command := range r.commands {
		if strings.Contains(strings.Join(command.Args, " "), fragment) {
			return true
		}
	}
	return false
}

func testAllocation() netutil.Allocation {
	return netutil.Allocation{
		WorkerID:         "worker-1",
		Namespace:        "vpnpool-1234567890",
		HostVeth:         "vph1234567890",
		NamespaceVeth:    "vpn1234567890",
		Subnet:           netip.MustParsePrefix("10.231.0.0/30"),
		HostAddress:      netip.MustParsePrefix("10.231.0.1/30"),
		NamespaceAddress: netip.MustParsePrefix("10.231.0.2/30"),
	}
}

package process

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestOSRunnerPassesArgumentsWithoutShellInterpretation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	literal := `$(touch /tmp/vpnpoold-must-not-exist); *; "quoted"`
	runner := OSRunner{}
	result, err := runner.Run(context.Background(), Command{
		Path: executable,
		Args: []string{"-test.run=TestHelperProcess", "--", literal},
		Env:  []string{"GO_WANT_VPNPOOLD_HELPER_PROCESS=1"},
	})
	if err != nil {
		t.Fatalf("Run() error = %v, stderr = %q", err, result.Stderr)
	}
	if result.Stdout != literal {
		t.Fatalf("stdout = %q, want literal %q", result.Stdout, literal)
	}
}

func TestOSRunnerLimitsCapturedOutput(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runner := OSRunner{OutputLimit: 8}
	result, err := runner.Run(context.Background(), Command{
		Path: executable,
		Args: []string{"-test.run=TestHelperProcess", "--", "0123456789abcdef"},
		Env:  []string{"GO_WANT_VPNPOOLD_HELPER_PROCESS=1"},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Stdout != "01234567" {
		t.Fatalf("stdout = %q", result.Stdout)
	}
}

func TestCommandValidation(t *testing.T) {
	tests := []struct {
		name    string
		command Command
	}{
		{name: "empty path", command: Command{}},
		{name: "relative path", command: Command{Path: "ip"}},
		{name: "NUL argument", command: Command{Path: "/usr/bin/ip", Args: []string{"link\x00show"}}},
		{name: "invalid environment", command: Command{Path: "/usr/bin/ip", Env: []string{"INVALID"}}},
		{name: "relative directory", command: Command{Path: "/usr/bin/ip", Dir: "tmp"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.command.Validate(); err == nil {
				t.Fatal("Validate() unexpectedly succeeded")
			}
		})
	}
}

func TestOSRunnerReturnsSanitizedExitError(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runner := OSRunner{}
	result, err := runner.Run(context.Background(), Command{
		Path: executable,
		Args: []string{"-test.run=TestHelperProcess", "--", "sensitive-argument"},
		Env: []string{
			"GO_WANT_VPNPOOLD_HELPER_PROCESS=1",
			"GO_VPNPOOLD_HELPER_EXIT=7",
		},
	})
	if err == nil {
		t.Fatal("Run() unexpectedly succeeded")
	}
	var runErr *RunError
	if !errors.As(err, &runErr) || runErr.ExitCode != 7 || result.ExitCode != 7 {
		t.Fatalf("Run() error = %#v, result = %#v", err, result)
	}
	if strings.Contains(err.Error(), "sensitive-argument") {
		t.Fatalf("error leaked arguments: %v", err)
	}
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_VPNPOOLD_HELPER_PROCESS") != "1" {
		return
	}
	separator := -1
	for index, arg := range os.Args {
		if arg == "--" {
			separator = index
			break
		}
	}
	if separator >= 0 {
		fmt.Print(strings.Join(os.Args[separator+1:], "\n"))
	}
	if value := os.Getenv("GO_VPNPOOLD_HELPER_EXIT"); value != "" {
		var code int
		_, _ = fmt.Sscanf(value, "%d", &code)
		os.Exit(code)
	}
	os.Exit(0)
}

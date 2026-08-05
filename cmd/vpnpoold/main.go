package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const defaultConfigPath = "/etc/vpnpoold/vpnpoold.yaml"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// exitError carries the process exit code alongside the message. Usage and
// validation problems exit 2; runtime failures exit 1. Preserving those codes
// matters because deploy/install.sh and the acceptance scripts branch on them.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func usageErrorf(format string, args ...any) error {
	return &exitError{code: 2, err: fmt.Errorf(format, args...)}
}

func runtimeErrorf(format string, args ...any) error {
	return &exitError{code: 1, err: fmt.Errorf(format, args...)}
}

func run(args []string, stdout, stderr io.Writer) int {
	root := newRootCommand(stdout, stderr)
	root.SetArgs(normalizeLegacyFlags(args))
	if err := root.Execute(); err != nil {
		var exit *exitError
		if errors.As(err, &exit) {
			fmt.Fprintln(stderr, exit.err)
			return exit.code
		}
		// Anything else is a pflag parse failure or an unknown command.
		fmt.Fprintln(stderr, err)
		return 2
	}
	return 0
}

// normalizeLegacyFlags rewrites the single-dash long flags accepted by the
// previous stdlib flag parser ("-config X") into the double-dash form pflag
// requires. Operator scripts, deploy/install.sh, docs/release.md and the
// disposable-VM acceptance suite all use the single-dash spelling, so dropping
// it would be a silent breaking change for existing deployments.
func normalizeLegacyFlags(args []string) []string {
	normalized := make([]string, 0, len(args))
	for index, argument := range args {
		if argument == "--" {
			normalized = append(normalized, args[index:]...)
			break
		}
		normalized = append(normalized, normalizeLegacyFlag(argument))
	}
	return normalized
}

func normalizeLegacyFlag(argument string) string {
	if len(argument) < 3 || argument[0] != '-' || argument[1] == '-' {
		return argument
	}
	name, _, _ := strings.Cut(argument[1:], "=")
	// A single-dash token is only a long flag when the name itself is longer
	// than one character; "-h" and clustered shorthands stay untouched.
	if len(name) < 2 {
		return argument
	}
	for index, character := range name {
		isLower := character >= 'a' && character <= 'z'
		isDigit := character >= '0' && character <= '9'
		// A flag name starts with a letter; "-5m" is a value, not a flag.
		if index == 0 && !isLower {
			return argument
		}
		if !isLower && !isDigit && character != '-' {
			return argument
		}
	}
	return "-" + argument
}

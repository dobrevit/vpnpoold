package openvpn

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dobrevit/vpnpoold/internal/process"
)

func TestFileCredentialProviderReadsPrivateSources(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	authFile := filepath.Join(directory, "auth")
	keyFile := filepath.Join(directory, "key")
	if err := os.WriteFile(authFile, []byte("alice\np a\"ss\\\\word\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("key secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := FileCredentialProvider{
		UsernamePasswordFile:   authFile,
		PrivateKeyPasswordFile: keyFile,
	}
	username, password, err := provider.UsernamePassword(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if username != "alice" || password != `p a"ss\\word` {
		t.Fatalf("credentials = %q/%q", username, password)
	}
	keyPassword, err := provider.PrivateKeyPassword(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if keyPassword != "key secret" {
		t.Fatalf("private-key password = %q", keyPassword)
	}
}

func TestFileCredentialProviderRejectsUnsafeFile(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "auth")
	if err := os.WriteFile(path, []byte("alice\nsecret\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	provider := FileCredentialProvider{UsernamePasswordFile: path}
	if _, _, err := provider.UsernamePassword(context.Background()); err == nil ||
		strings.Contains(err.Error(), path) {
		t.Fatalf("UsernamePassword() error = %v", err)
	}
}

func TestFileCredentialProviderRunsBoundedChallengeHelper(t *testing.T) {
	runner := &credentialRunner{result: process.Result{Stdout: "8675309\n"}}
	provider := FileCredentialProvider{
		ChallengeCommand: "/usr/local/libexec/vpnpoold-otp",
		ChallengeTimeout: time.Second,
		Runner:           runner,
	}
	challenge := Challenge{
		Kind: ChallengeDynamic, Text: "Token PIN", Echo: false,
		ResponseRequired: true,
	}
	response, err := provider.ChallengeResponse(context.Background(), challenge)
	if err != nil {
		t.Fatal(err)
	}
	if response != "8675309" {
		t.Fatalf("response = %q", response)
	}
	if runner.command.Path != provider.ChallengeCommand ||
		len(runner.command.Args) != 0 {
		t.Fatalf("helper command = %+v", runner.command)
	}
	var request Challenge
	if err := json.Unmarshal(runner.command.Stdin, &request); err != nil {
		t.Fatalf("helper stdin = %q: %v", runner.command.Stdin, err)
	}
	if request != challenge {
		t.Fatalf("helper request = %+v, want %+v", request, challenge)
	}
}

func TestFileCredentialProviderDoesNotExposeHelperOutputOnFailure(t *testing.T) {
	provider := FileCredentialProvider{
		ChallengeCommand: "/usr/local/libexec/vpnpoold-otp",
		Runner: &credentialRunner{
			result: process.Result{Stderr: "secret helper diagnostics"},
			err:    errors.New("secret execution error"),
		},
	}
	_, err := provider.ChallengeResponse(context.Background(), Challenge{
		Kind: ChallengeStatic, ResponseRequired: true,
	})
	if err == nil ||
		strings.Contains(err.Error(), "secret") ||
		strings.Contains(err.Error(), provider.ChallengeCommand) {
		t.Fatalf("ChallengeResponse() error = %v", err)
	}
}

type credentialRunner struct {
	command process.Command
	result  process.Result
	err     error
}

func (r *credentialRunner) Run(
	_ context.Context,
	command process.Command,
) (process.Result, error) {
	command.Stdin = append([]byte(nil), command.Stdin...)
	r.command = command
	return r.result, r.err
}

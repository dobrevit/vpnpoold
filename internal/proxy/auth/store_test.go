package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestDecodeAndAuthenticate(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	input := "users:\n  alice:\n    password_hash: " + string(hash) + "\n"
	store, err := Decode(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if !store.Authenticate("alice", []byte("correct horse")) {
		t.Fatal("correct password was rejected")
	}
	if store.Authenticate("alice", []byte("wrong")) {
		t.Fatal("wrong password was accepted")
	}
	if store.Authenticate("unknown", []byte("correct horse")) {
		t.Fatal("unknown user was accepted")
	}
}

func TestDecodeRejectsUnsafeContent(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "plaintext field", input: "users:\n  alice:\n    password: secret\n"},
		{name: "empty", input: "users: {}\n"},
		{name: "invalid username", input: "users:\n  \"bad user\":\n    password_hash: nope\n"},
		{name: "invalid hash", input: "users:\n  alice:\n    password_hash: plaintext\n"},
		{name: "multiple documents", input: "users: {}\n---\nusers: {}\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(test.input)); err == nil {
				t.Fatal("Decode() unexpectedly succeeded")
			}
		})
	}
}

func TestLoadRequiresPrivatePermissions(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "users.yaml")
	if err := os.WriteFile(path, []byte("users: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadRejectsUsersFileSymlink(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "users.yaml")
	link := filepath.Join(directory, "users-link.yaml")
	if err := os.WriteFile(path, []byte("users: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil ||
		!strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("Load() error = %v", err)
	}
}

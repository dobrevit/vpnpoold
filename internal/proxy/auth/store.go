package auth

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

const maxUsersFileBytes = 1024 * 1024

type userFile struct {
	Users map[string]userEntry `yaml:"users"`
}

type userEntry struct {
	PasswordHash string `yaml:"password_hash"`
}

type Store struct {
	hashes map[string][]byte
	dummy  []byte
}

func Load(path string) (*Store, error) {
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("users file parent directory must not be writable by group or other users")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("users file is unavailable")
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("users file must be a regular file, not a symbolic link")
	}
	if before.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("users file must not be accessible by group or other users")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open users file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, errors.New("inspect opened users file")
	}
	after, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() ||
		!os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return nil, errors.New("users file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxUsersFileBytes+1))
	if err != nil {
		return nil, errors.New("read users file")
	}
	if len(data) > maxUsersFileBytes {
		return nil, errors.New("users file is too large")
	}
	return Decode(bytes.NewReader(data))
}

func Decode(reader io.Reader) (*Store, error) {
	var input userFile
	decoder := yaml.NewDecoder(reader)
	decoder.KnownFields(true)
	if err := decoder.Decode(&input); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("users file is empty")
		}
		return nil, fmt.Errorf("decode users file: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, errors.New("decode trailing users document")
		}
		return nil, errors.New("multiple YAML documents are not allowed in users file")
	}
	if len(input.Users) == 0 {
		return nil, errors.New("users file must contain at least one user")
	}

	store := &Store{hashes: make(map[string][]byte, len(input.Users))}
	for username, entry := range input.Users {
		if !validUsername(username) {
			return nil, errors.New("users file contains an invalid username")
		}
		hash := []byte(entry.PasswordHash)
		cost, err := bcrypt.Cost(hash)
		if err != nil {
			return nil, errors.New("users file contains an invalid bcrypt password hash")
		}
		if cost < bcrypt.DefaultCost {
			return nil, fmt.Errorf("bcrypt cost must be at least %d", bcrypt.DefaultCost)
		}
		store.hashes[username] = append([]byte(nil), hash...)
		if store.dummy == nil {
			store.dummy = append([]byte(nil), hash...)
		}
	}
	return store, nil
}

func (s *Store) Authenticate(username string, password []byte) bool {
	if s == nil {
		return false
	}
	hash, exists := s.hashes[username]
	if !exists {
		_ = bcrypt.CompareHashAndPassword(s.dummy, password)
		return false
	}
	return bcrypt.CompareHashAndPassword(hash, password) == nil
}

func validUsername(username string) bool {
	if len(username) == 0 || len(username) > 255 || strings.TrimSpace(username) != username {
		return false
	}
	for _, value := range []byte(username) {
		if value < 0x21 || value > 0x7e {
			return false
		}
	}
	return true
}

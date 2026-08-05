package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

var errHostPrerequisites = errors.New("host prerequisites are incomplete")

// absoluteExecutable resolves a privileged helper (ip, nft, openvpn) and holds
// it to the same trust standard the configuration applies to openvpn.binary:
// a regular, non-group/other-writable file owned by root or the daemon user,
// in a directory with the same properties.
func absoluteExecutable(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve executable symlinks: %w", err)
	}
	if err := validateTrustedExecutable(path, uint32(os.Geteuid())); err != nil {
		return "", err
	}
	return path, nil
}

func validateTrustedExecutable(path string, daemonUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("executable must be a regular file")
	}
	if info.Mode().Perm()&0o111 == 0 {
		return errors.New("executable file is not executable")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("executable must not be writable by group or other users")
	}
	if !trustedFileOwner(info, daemonUID) {
		return errors.New("executable must be owned by root or the daemon user")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("inspect executable directory: %w", err)
	}
	if !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 {
		return errors.New("executable directory must not be writable by group or other users")
	}
	if !trustedFileOwner(parent, daemonUID) {
		return errors.New("executable directory must be owned by root or the daemon user")
	}
	return nil
}

func trustedFileOwner(info os.FileInfo, daemonUID uint32) bool {
	status, ok := info.Sys().(*syscall.Stat_t)
	return ok && (status.Uid == 0 || status.Uid == daemonUID)
}

func ensureServiceDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("directory path must be absolute")
	}
	if err := os.MkdirAll(path, 0o750); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("path is not a directory")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("directory must not be writable by group or other")
	}
	return nil
}

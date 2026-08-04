package daemon

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

// The abstract Unix address is scoped to the host network namespace and has no
// filesystem permissions or stale path to manage. This protects the single
// global vpnpoold_host nftables table even if two configurations use different
// runtime directories.
const instanceLockAddress = "\x00vpnpoold-daemon-instance"

type InstanceLock struct {
	listener *net.UnixListener
	once     sync.Once
}

func AcquireInstanceLock() (*InstanceLock, error) {
	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: instanceLockAddress, Net: "unix"},
	)
	if err != nil {
		return nil, fmt.Errorf("another vpnpoold daemon may already be running: %w", err)
	}
	return &InstanceLock{listener: listener}, nil
}

func (l *InstanceLock) Close() error {
	if l == nil || l.listener == nil {
		return nil
	}
	var closeErr error
	l.once.Do(func() {
		closeErr = l.listener.Close()
	})
	if errors.Is(closeErr, net.ErrClosed) {
		return nil
	}
	return closeErr
}

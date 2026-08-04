package daemon

import "testing"

func TestInstanceLockIsExclusiveAndReleasable(t *testing.T) {
	first, err := AcquireInstanceLock()
	if err != nil {
		t.Fatalf("first AcquireInstanceLock() error = %v", err)
	}
	defer first.Close()
	if second, err := AcquireInstanceLock(); err == nil {
		_ = second.Close()
		t.Fatal("second AcquireInstanceLock() unexpectedly succeeded")
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	third, err := AcquireInstanceLock()
	if err != nil {
		t.Fatalf("AcquireInstanceLock() after release error = %v", err)
	}
	if err := third.Close(); err != nil {
		t.Fatalf("third Close() error = %v", err)
	}
}

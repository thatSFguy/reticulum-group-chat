//go:build !windows

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestInstanceLockBlocksSecondAcquire(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json.lock")

	release1, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatalf("first acquire should succeed: %v", err)
	}

	// A second acquire on the same path — as an orphaned/duplicate process
	// would attempt — must be refused with errInstanceHeld, and the error
	// must name the holder's PID so the refusal is self-diagnosing.
	_, err = acquireInstanceLock(path)
	if !errors.Is(err, errInstanceHeld) {
		t.Fatalf("second acquire = %v, want errInstanceHeld", err)
	}
	wantPID := fmt.Sprintf("by PID %d", os.Getpid())
	if !strings.Contains(err.Error(), wantPID) {
		t.Errorf("refusal error %q does not name the holder (%s)", err, wantPID)
	}

	// After the first holder releases, the lock is available again.
	release1()
	release2, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatalf("acquire after release should succeed: %v", err)
	}
	release2()
}

// A lock held by a process that wrote no PID (a pre-1.12.1 build) still
// refuses with plain errInstanceHeld — no bogus holder in the message.
func TestInstanceLockRefusalWithoutRecordedPID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("raw flock: %v", err)
	}

	_, err = acquireInstanceLock(path)
	if !errors.Is(err, errInstanceHeld) {
		t.Fatalf("acquire = %v, want errInstanceHeld", err)
	}
	if strings.Contains(err.Error(), "by PID") {
		t.Errorf("refusal %q names a PID, but the holder never recorded one", err)
	}
}

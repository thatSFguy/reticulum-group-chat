//go:build !windows

package service

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestInstanceLockBlocksSecondAcquire(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json.lock")

	release1, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatalf("first acquire should succeed: %v", err)
	}

	// A second acquire on the same path — as an orphaned/duplicate process
	// would attempt — must be refused with errInstanceHeld.
	if _, err := acquireInstanceLock(path); !errors.Is(err, errInstanceHeld) {
		t.Fatalf("second acquire = %v, want errInstanceHeld", err)
	}

	// After the first holder releases, the lock is available again.
	release1()
	release2, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatalf("acquire after release should succeed: %v", err)
	}
	release2()
}

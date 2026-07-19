//go:build !windows

package service

import (
	"errors"
	"os"
	"syscall"
)

// acquireInstanceLock takes an exclusive, non-blocking advisory lock (flock)
// on path and returns a release func on success. If another process already
// holds the lock it returns errInstanceHeld; any other error means the lock
// could not be evaluated (e.g. a filesystem that doesn't support flock, such
// as some NFS mounts) and the caller may continue without the guard.
//
// flock is released automatically when the process exits — including on a
// crash — so a restart that kills the old process hands the lock over
// cleanly, while an orphaned old process keeps it and makes the new one
// refuse to start (which is exactly what prevents duplicate fan-out).
func acquireInstanceLock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errInstanceHeld
		}
		return nil, err
	}
	// Keep f open (referenced by the closure) so the lock is held for the
	// life of the process; releasing closes the fd, which drops the lock.
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

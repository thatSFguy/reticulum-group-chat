//go:build !windows

package service

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// acquireInstanceLock takes an exclusive, non-blocking advisory lock (flock)
// on path and returns a release func on success. If another process already
// holds the lock it returns errInstanceHeld — wrapped with the holder's PID
// when one can be read back from the lockfile; any other error means the lock
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
		if errors.Is(err, syscall.EWOULDBLOCK) {
			// The holder wrote its PID into the lockfile on acquire; read
			// it back so the refusal names the process to kill instead of
			// sending the operator process-hunting.
			holder := readLockHolder(f)
			_ = f.Close()
			if holder != "" {
				return nil, fmt.Errorf("%w by PID %s", errInstanceHeld, holder)
			}
			return nil, errInstanceHeld
		}
		_ = f.Close()
		return nil, err
	}
	// Record our PID for the next refused instance's error message.
	// Best-effort: the flock is the guard, the PID is a courtesy — stale
	// content is never read unlocked, because refusals only read while the
	// writer still holds the lock.
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	// Keep f open (referenced by the closure) so the lock is held for the
	// life of the process; releasing closes the fd, which drops the lock.
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// readLockHolder returns the PID recorded in the lockfile by the current
// holder, or "" if the file is empty or doesn't contain a plain PID (e.g. a
// lockfile created by a pre-1.12.1 build, which wrote nothing).
func readLockHolder(f *os.File) string {
	buf := make([]byte, 32)
	n, _ := f.ReadAt(buf, 0)
	s := strings.TrimSpace(string(buf[:n]))
	if _, err := strconv.Atoi(s); err != nil || s == "" {
		return ""
	}
	return s
}

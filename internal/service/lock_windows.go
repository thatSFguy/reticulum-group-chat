//go:build windows

package service

// acquireInstanceLock is a no-op on Windows: the stdlib syscall package has
// no flock, and we avoid pulling in an external dependency just for this.
// Single-instance protection is therefore NOT enforced on Windows — run one
// fwdsvc per config manually. Returns a no-op release and never reports
// errInstanceHeld.
func acquireInstanceLock(path string) (func(), error) {
	return func() {}, nil
}

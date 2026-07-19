package service

import "errors"

// errInstanceHeld is returned by acquireInstanceLock when another process
// already holds the single-instance lock for a state_path. The caller treats
// it as fatal (refuse to start); any other error from acquireInstanceLock
// means the lock couldn't be evaluated and startup may continue without the
// guard. See lock_unix.go / lock_windows.go for the platform implementations.
var errInstanceHeld = errors.New("instance lock already held")

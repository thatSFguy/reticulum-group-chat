//go:build !unix

package logging

import "os"

// isJournal is always false off Unix: there is no journald to talk to, and
// Windows builds write to a console or a log_path file.
func isJournal(*os.File) bool { return false }

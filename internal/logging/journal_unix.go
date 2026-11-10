//go:build unix

package logging

import (
	"fmt"
	"os"
	"syscall"
)

// isJournal reports whether f is the stream systemd connected to journald.
//
// systemd sets JOURNAL_STREAM="<device>:<inode>" for a service whose stdout
// or stderr goes to the journal (systemd.exec(5)). The variable alone is not
// enough: it is inherited by children, so a shell started from a service, or
// a unit that redirects stdout to a file, would still have it set. Matching
// it against f's own device and inode is the check systemd documents, and it
// keeps "<4>" out of a terminal or a redirected file.
func isJournal(f *os.File) bool {
	want := os.Getenv("JOURNAL_STREAM")
	if want == "" || f == nil {
		return false
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return false
	}
	return want == fmt.Sprintf("%d:%d", uint64(st.Dev), uint64(st.Ino))
}

//go:build unix

package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestIsJournal(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "stream"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}

	t.Setenv("JOURNAL_STREAM", "")
	if isJournal(f) {
		t.Error("journal detected with JOURNAL_STREAM unset")
	}
	t.Setenv("JOURNAL_STREAM", fmt.Sprintf("%d:%d", uint64(st.Dev), uint64(st.Ino)))
	if !isJournal(f) {
		t.Error("journal not detected when JOURNAL_STREAM matches the stream")
	}
	// Inherited variable, different stream: a shell spawned from a unit,
	// or stdout redirected to a file.
	t.Setenv("JOURNAL_STREAM", fmt.Sprintf("%d:%d", uint64(st.Dev), uint64(st.Ino)+1))
	if isJournal(f) {
		t.Error("journal detected for a stream JOURNAL_STREAM does not name")
	}
}

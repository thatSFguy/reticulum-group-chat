package logging

import (
	"bytes"
	"testing"
	"time"

	"github.com/thatSFguy/reticulum-go/rns"
)

// The point of this type is to be handed to reticulum-go and keep the
// library's severities, so fail the build if it stops qualifying.
var _ rns.LeveledLogger = (*Logger)(nil)

func fixed(l *Logger) *Logger {
	l.now = func() time.Time { return time.Date(2026, 11, 10, 1, 2, 3, 456789000, time.UTC) }
	return l
}

func TestPlainFormat(t *testing.T) {
	var buf bytes.Buffer
	l := fixed(NewWriter(&buf, false, rns.LogDebug))
	l.Warnf("disk %s", "full")
	l.Printf("unlabelled")
	want := "fwdsvc 2026/11/10 01:02:03.456789 WARN  disk full\n" +
		"fwdsvc 2026/11/10 01:02:03.456789 INFO  unlabelled\n"
	if buf.String() != want {
		t.Fatalf("got:\n%q\nwant:\n%q", buf.String(), want)
	}
}

// Every journald line needs its own prefix: an unprefixed continuation
// line is filed as info and would slip past LogLevelMax=warning.
func TestJournalPrefixes(t *testing.T) {
	var buf bytes.Buffer
	l := fixed(NewWriter(&buf, true, rns.LogDebug))
	l.Errorf("a")
	l.Warnf("b\nc\n")
	l.Infof("d")
	l.Debugf("e")
	want := "<3>fwdsvc 2026/11/10 01:02:03.456789 ERROR a\n" +
		"<4>fwdsvc 2026/11/10 01:02:03.456789 WARN  b\n<4>c\n" +
		"<6>fwdsvc 2026/11/10 01:02:03.456789 INFO  d\n" +
		"<7>fwdsvc 2026/11/10 01:02:03.456789 DEBUG e\n"
	if buf.String() != want {
		t.Fatalf("got:\n%q\nwant:\n%q", buf.String(), want)
	}
}

func TestThreshold(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriter(&buf, false, rns.LogWarn)
	l.Debugf("no")
	l.Infof("no")
	l.Printf("no")
	l.Warnf("yes")
	l.Errorf("yes")
	if got := bytes.Count(buf.Bytes(), []byte("\n")); got != 2 {
		t.Fatalf("warn threshold wrote %d lines, want 2:\n%s", got, buf.String())
	}
	if bytes.Contains(buf.Bytes(), []byte("no")) {
		t.Fatalf("a below-threshold line was written:\n%s", buf.String())
	}
	if l.Enabled(rns.LogInfo) || !l.Enabled(rns.LogWarn) {
		t.Fatal("Enabled disagrees with the threshold")
	}
}

// The log_path copy never carries "<N>": it is read with less and grep,
// not by journald.
func TestFileCopyIsPlain(t *testing.T) {
	var console, file bytes.Buffer
	l := fixed(NewWriter(&console, true, rns.LogInfo))
	l.file = &file
	l.Warnf("x")
	if want := "fwdsvc 2026/11/10 01:02:03.456789 WARN  x\n"; file.String() != want {
		t.Fatalf("file got %q, want %q", file.String(), want)
	}
	if console.String() != "<4>"+file.String() {
		t.Fatalf("console got %q", console.String())
	}
}

// Package logging is fwdsvc's levelled logger.
//
// WHY not log/slog: every line fwdsvc and reticulum-go emit is a
// human-written Printf sentence that operators grep for ("inbound stamp:",
// "resource sender: complete", "new sender contact:"). slog would turn those
// into key=value records and break every grep and every doc that quotes
// them. What operators actually asked for was narrower: a severity on each
// line, so the journal can be filtered, and a threshold so a busy hub can be
// told to keep quiet. This package adds exactly that and keeps the text.
//
// Severity reaches journald as an sd-daemon(3) priority prefix — "<4>" for
// a warning — at the start of each line. journald strips the prefix and
// records it as PRIORITY=, which is what `journalctl -p warning` filters on
// and what `LogLevelMax=warning` in a systemd unit discards at ingestion.
// The prefix is written only when the console stream really is the journal
// (see isJournal): on a terminal, or in a log_path file, "<4>" would be
// noise, so those get a plain WARN/INFO label instead.
package logging

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/thatSFguy/reticulum-go/rns"
)

// Logger implements rns.Logger and rns.LeveledLogger, so it can be handed
// to reticulum-go directly and the library's own severities survive.
type Logger struct {
	mu      sync.Mutex
	min     rns.LogLevel
	console io.Writer
	journal bool
	file    io.Writer
	now     func() time.Time
}

// New logs to console (stdout for the daemon, stderr for main's pre-service
// lines) and, if file is non-nil, also to file. Lines below min are dropped
// before formatting. Whether console gets journald priority prefixes is
// detected from the stream itself.
func New(console *os.File, file io.Writer, min rns.LogLevel) *Logger {
	return &Logger{
		min:     min,
		console: console,
		journal: isJournal(console),
		file:    file,
		now:     time.Now,
	}
}

// NewWriter is New with the journal decision made by the caller. Tests use
// it to assert the exact bytes of both formats.
func NewWriter(console io.Writer, journal bool, min rns.LogLevel) *Logger {
	return &Logger{min: min, console: console, journal: journal, now: time.Now}
}

// Discard returns a logger that writes nothing, for tests.
func Discard() *Logger { return NewWriter(io.Discard, false, rns.LogError+1) }

// Enabled reports whether a line at level would be written. Use it to skip
// building an expensive argument, not as a substitute for picking a level.
func (l *Logger) Enabled(level rns.LogLevel) bool { return level >= l.min }

// Logf satisfies rns.LeveledLogger.
func (l *Logger) Logf(level rns.LogLevel, format string, args ...any) {
	if level < l.min {
		return
	}
	msg := strings.TrimSuffix(fmt.Sprintf(format, args...), "\n")
	body := fmt.Sprintf("fwdsvc %s %s %s\n",
		l.now().Format("2006/01/02 15:04:05.000000"), label(level), msg)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.journal {
		// journald assigns a priority per line, and a line without a
		// prefix defaults to info. A message with an embedded newline
		// would otherwise have its continuation lines escape a
		// LogLevelMax=warning filter — prefix every one of them.
		p := fmt.Sprintf("<%d>", priority(level))
		io.WriteString(l.console, p+strings.ReplaceAll(strings.TrimSuffix(body, "\n"), "\n", "\n"+p)+"\n")
	} else {
		io.WriteString(l.console, body)
	}
	if l.file != nil {
		io.WriteString(l.file, body)
	}
}

// Printf satisfies rns.Logger. An unlabelled line is info — which is what
// every line was before levels existed.
func (l *Logger) Printf(format string, args ...any) { l.Logf(rns.LogInfo, format, args...) }

func (l *Logger) Debugf(format string, args ...any) { l.Logf(rns.LogDebug, format, args...) }
func (l *Logger) Infof(format string, args ...any)  { l.Logf(rns.LogInfo, format, args...) }
func (l *Logger) Warnf(format string, args ...any)  { l.Logf(rns.LogWarn, format, args...) }
func (l *Logger) Errorf(format string, args ...any) { l.Logf(rns.LogError, format, args...) }

// label is fixed-width so columns line up in a file or terminal.
func label(level rns.LogLevel) string {
	switch {
	case level >= rns.LogError:
		return "ERROR"
	case level >= rns.LogWarn:
		return "WARN "
	case level >= rns.LogInfo:
		return "INFO "
	}
	return "DEBUG"
}

// priority maps to syslog(3) severities: err=3, warning=4, info=6,
// debug=7. Notice (5) is skipped: nothing here is "normal but
// significant" in a way that would justify a fifth level.
func priority(level rns.LogLevel) int {
	switch {
	case level >= rns.LogError:
		return 3
	case level >= rns.LogWarn:
		return 4
	case level >= rns.LogInfo:
		return 6
	}
	return 7
}

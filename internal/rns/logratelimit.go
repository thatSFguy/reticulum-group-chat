package rns

import (
	"sync"
	"time"
)

// rateLimitedLogger wraps a Logger for use on the packet dispatcher's
// error paths.
//
// WHY: the dispatcher logs inline on every parse failure, verify
// failure, unknown link id and bad proof, and the production logger
// writes synchronously — under a mutex — to both a file and stdout. A
// flood of malformed packets therefore forces one blocking write(2) per
// packet on the single goroutine that handles ALL inbound traffic. If
// stdout is a pipe whose reader has stalled (journald backpressure,
// `| tee`), inbound processing stops entirely. It is also unbounded,
// remote-driven disk growth: there is no log rotation.
//
// Policy: allow a short burst so ordinary diagnostics still appear
// immediately, then throttle to one line per interval per category,
// reporting how many were suppressed. Categories are caller-supplied
// constants (never attacker-controlled strings), so the map is bounded
// by the number of call sites.
type rateLimitedLogger struct {
	inner Logger

	mu       sync.Mutex
	counters map[string]*logCounter
	burst    int
	interval time.Duration
}

type logCounter struct {
	windowStart time.Time
	inWindow    int
	suppressed  int
}

// Defaults: 5 lines immediately, then at most 1 line per 10s per
// category, each carrying the suppressed count.
const (
	defaultLogBurst    = 5
	defaultLogInterval = 10 * time.Second
)

func newRateLimitedLogger(inner Logger) *rateLimitedLogger {
	if inner == nil {
		inner = noopLogger{}
	}
	return &rateLimitedLogger{
		inner:    inner,
		counters: map[string]*logCounter{},
		burst:    defaultLogBurst,
		interval: defaultLogInterval,
	}
}

// Printf emits an unthrottled line. Use for events driven by our own
// actions or by configuration, not by inbound packets.
func (l *rateLimitedLogger) Printf(format string, args ...any) {
	l.inner.Printf(format, args...)
}

// Limited emits at most `burst` lines per `interval` for the given
// category, appending a suppression count when lines were dropped.
// Categories MUST be compile-time constants — never attacker-controlled
// text — so the counter map stays bounded.
func (l *rateLimitedLogger) Limited(category, format string, args ...any) {
	now := time.Now()

	l.mu.Lock()
	c, ok := l.counters[category]
	if !ok {
		c = &logCounter{windowStart: now}
		l.counters[category] = c
	}
	if now.Sub(c.windowStart) >= l.interval {
		// Window rolled: report what we dropped, then reset.
		dropped := c.suppressed
		c.windowStart = now
		c.inWindow = 0
		c.suppressed = 0
		if dropped > 0 {
			l.mu.Unlock()
			l.inner.Printf("(%s: %d further messages suppressed in the last %s)",
				category, dropped, l.interval)
			l.mu.Lock()
		}
	}
	if c.inWindow >= l.burst {
		c.suppressed++
		l.mu.Unlock()
		return
	}
	c.inWindow++
	l.mu.Unlock()

	l.inner.Printf(format, args...)
}

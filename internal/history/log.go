package history

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Entry struct {
	At         time.Time `json:"at"`
	SenderHash string    `json:"sender_hash"`
	SenderNick string    `json:"sender_nick"`
	Content    string    `json:"content"`
}

type Log struct {
	mu       sync.Mutex
	path     string
	capacity int
	entries  []Entry
}

type fileFormat struct {
	Messages []Entry `json:"messages"`
}

func New(path string, capacity int) (*Log, error) {
	if capacity < 1 {
		capacity = 1
	}
	l := &Log{path: path, capacity: capacity}
	if err := l.load(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Log) load() error {
	data, err := os.ReadFile(l.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		return err
	}
	if len(f.Messages) > l.capacity {
		f.Messages = f.Messages[len(f.Messages)-l.capacity:]
	}
	l.entries = f.Messages
	return nil
}

func (l *Log) Append(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
	if len(l.entries) > l.capacity {
		l.entries = l.entries[len(l.entries)-l.capacity:]
	}
	return l.persistLocked()
}

// SinceOldest returns entries (oldest first) whose At is at or after the
// given cutoff. cutoff.IsZero() means "no time filter".
func (l *Log) SinceOldest(cutoff time.Time) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if cutoff.IsZero() {
		out := make([]Entry, len(l.entries))
		copy(out, l.entries)
		return out
	}
	out := make([]Entry, 0, len(l.entries))
	for _, e := range l.entries {
		if !e.At.Before(cutoff) {
			out = append(out, e)
		}
	}
	return out
}

func (l *Log) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

func (l *Log) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(fileFormat{Messages: l.entries}, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(l.path, data, 0o600)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

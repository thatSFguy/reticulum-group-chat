package history

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRingEvictsOldest(t *testing.T) {
	dir := t.TempDir()
	l, err := New(filepath.Join(dir, "h.json"), 3)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		_ = l.Append(Entry{
			At:         t0.Add(time.Duration(i) * time.Minute),
			SenderHash: "h",
			SenderNick: "n",
			Content:    "msg",
		})
	}
	got := l.SinceOldest(time.Time{})
	if len(got) != 3 {
		t.Fatalf("expected ring=3, got %d", len(got))
	}
	if !got[0].At.Equal(t0.Add(2 * time.Minute)) {
		t.Errorf("expected oldest survivor at t0+2m, got %v", got[0].At)
	}
}

func TestSinceOldestRespectsCutoff(t *testing.T) {
	dir := t.TempDir()
	l, _ := New(filepath.Join(dir, "h.json"), 100)
	t0 := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		_ = l.Append(Entry{At: t0.Add(time.Duration(i) * time.Hour)})
	}
	cutoff := t0.Add(5 * time.Hour)
	got := l.SinceOldest(cutoff)
	if len(got) != 5 {
		t.Errorf("expected 5 (entries at +5h..+9h), got %d", len(got))
	}
	for _, e := range got {
		if e.At.Before(cutoff) {
			t.Errorf("entry %v before cutoff %v", e.At, cutoff)
		}
	}
}

func TestPersistAcrossReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "h.json")

	l, _ := New(path, 5)
	_ = l.Append(Entry{
		At:         time.Now(),
		SenderHash: "abc",
		SenderNick: "nick",
		Content:    "hello",
	})

	l2, err := New(path, 5)
	if err != nil {
		t.Fatal(err)
	}
	got := l2.SinceOldest(time.Time{})
	if len(got) != 1 || got[0].Content != "hello" {
		t.Errorf("expected reloaded entry, got %+v", got)
	}
}

func TestCapacityShrinkOnReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "h.json")

	l, _ := New(path, 100)
	for i := 0; i < 50; i++ {
		_ = l.Append(Entry{At: time.Now()})
	}

	l2, _ := New(path, 10)
	if l2.Len() != 10 {
		t.Errorf("expected truncation to capacity=10, got %d", l2.Len())
	}
}

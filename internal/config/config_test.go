package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"1d", 24 * time.Hour},
		{"4w", 4 * 7 * 24 * time.Hour},
		{"30s", 30 * time.Second},
		{"15m", 15 * time.Minute},
		{"2h", 2 * time.Hour},
	}
	for _, c := range cases {
		got, err := ParseDuration(c.in)
		if err != nil {
			t.Errorf("ParseDuration(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseDuration(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	if _, err := ParseDuration("nope"); err == nil {
		t.Error("ParseDuration(\"nope\") expected error")
	}
}

func TestNormalizeRejectsBadHashes(t *testing.T) {
	cfg := &Config{
		Service: ServiceConfig{
			DisplayName:   "x",
			IdentityPath:  "/tmp/id",
			StatePath:     "/tmp/st",
			HistoryPath:   "/tmp/hi",
			PruneAfter:    Duration(time.Hour),
			PruneInterval: Duration(time.Minute),
		},
		Reticulum: ReticulumConfig{ConfigPath: "/tmp/r"},
		Replay:    ReplayConfig{Count: 0, MaxAge: Duration(0)},
		Admins:    []string{"not-hex"},
	}
	if err := cfg.normalize(); err == nil {
		t.Fatal("expected normalize to reject non-hex admin")
	}
}

func TestNormalizeAcceptsValidHashes(t *testing.T) {
	cfg := &Config{
		Service: ServiceConfig{
			DisplayName:   "x",
			IdentityPath:  "/tmp/id",
			StatePath:     "/tmp/st",
			HistoryPath:   "/tmp/hi",
			PruneAfter:    Duration(time.Hour),
			PruneInterval: Duration(time.Minute),
		},
		Reticulum: ReticulumConfig{ConfigPath: "/tmp/r"},
		Replay:    ReplayConfig{Count: 100, MaxAge: Duration(time.Hour)},
		Admins:    []string{"00112233445566778899aabbccddeeff"},
		Mods:      []string{"FFEEDDCCBBAA99887766554433221100"},
	}
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if cfg.Mods[0] != "ffeeddccbbaa99887766554433221100" {
		t.Errorf("expected mod hash to be lowercased, got %q", cfg.Mods[0])
	}
	if !cfg.IsAdmin("00112233445566778899AABBCCDDEEFF") {
		t.Error("IsAdmin should be case-insensitive")
	}
	if cfg.IsMod("00000000000000000000000000000000") {
		t.Error("IsMod false-positive")
	}
}

func TestNormalizeRejectsBadDurations(t *testing.T) {
	cases := []ServiceConfig{
		{DisplayName: "x", PruneAfter: Duration(0), PruneInterval: Duration(time.Hour)},
		{DisplayName: "x", PruneAfter: Duration(time.Hour), PruneInterval: Duration(0)},
		{DisplayName: "", PruneAfter: Duration(time.Hour), PruneInterval: Duration(time.Hour)},
	}
	for i, sc := range cases {
		cfg := &Config{
			Service:   sc,
			Reticulum: ReticulumConfig{ConfigPath: "/tmp/r"},
			Replay:    ReplayConfig{Count: 0, MaxAge: 0},
		}
		cfg.Service.IdentityPath = "/tmp/id"
		cfg.Service.StatePath = "/tmp/st"
		cfg.Service.HistoryPath = "/tmp/hi"
		if err := cfg.normalize(); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

func TestExpandPath(t *testing.T) {
	out, err := ExpandPath("~/x")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(out) != "x" {
		t.Errorf("ExpandPath(~/x) = %q", out)
	}
	out, _ = ExpandPath("")
	if out != "" {
		t.Errorf("ExpandPath(\"\") = %q, want \"\"", out)
	}
}

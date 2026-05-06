package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

const identityHashLen = 16

type Config struct {
	Service   ServiceConfig   `toml:"service"`
	Reticulum ReticulumConfig `toml:"reticulum"`
	Replay    ReplayConfig    `toml:"replay"`
	Admins    []string        `toml:"admins"`
	Mods      []string        `toml:"mods"`
}

type ServiceConfig struct {
	DisplayName   string        `toml:"display_name"`
	IdentityPath  string        `toml:"identity_path"`
	StatePath     string        `toml:"state_path"`
	HistoryPath   string        `toml:"history_path"`
	PruneAfter    Duration      `toml:"prune_after"`
	PruneInterval Duration      `toml:"prune_interval"`
}

type ReticulumConfig struct {
	ConfigPath string `toml:"config_path"`
}

type ReplayConfig struct {
	Count  int      `toml:"count"`
	MaxAge Duration `toml:"max_age"`
}

// Duration extends Go's time.Duration with a "d" (day) and "w" (week) suffix
// since 4-week prune windows are awkward to express in stdlib units.
type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Std() time.Duration { return time.Duration(d) }

var extDurRE = regexp.MustCompile(`^(\d+)([dw])$`)

func ParseDuration(s string) (time.Duration, error) {
	if m := extDurRE.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		switch m[2] {
		case "d":
			return time.Duration(n) * 24 * time.Hour, nil
		case "w":
			return time.Duration(n) * 7 * 24 * time.Hour, nil
		}
	}
	return time.ParseDuration(s)
}

func Load(path string) (*Config, error) {
	expanded, err := ExpandPath(path)
	if err != nil {
		return nil, err
	}
	c := defaults()
	if _, err := toml.DecodeFile(expanded, c); err != nil {
		return nil, fmt.Errorf("read config %s: %w", expanded, err)
	}
	if err := c.normalize(); err != nil {
		return nil, err
	}
	return c, nil
}

func defaults() *Config {
	return &Config{
		Service: ServiceConfig{
			DisplayName:   "Forwarder",
			IdentityPath:  "~/.fwdsvc/identity",
			StatePath:     "~/.fwdsvc/state.json",
			HistoryPath:   "~/.fwdsvc/history.json",
			PruneAfter:    Duration(4 * 7 * 24 * time.Hour),
			PruneInterval: Duration(1 * time.Hour),
		},
		Reticulum: ReticulumConfig{
			ConfigPath: "~/.reticulum",
		},
		Replay: ReplayConfig{
			Count:  100,
			MaxAge: Duration(7 * 24 * time.Hour),
		},
	}
}

func (c *Config) normalize() error {
	for _, p := range []*string{
		&c.Service.IdentityPath,
		&c.Service.StatePath,
		&c.Service.HistoryPath,
		&c.Reticulum.ConfigPath,
	} {
		ex, err := ExpandPath(*p)
		if err != nil {
			return err
		}
		*p = ex
	}

	if strings.TrimSpace(c.Service.DisplayName) == "" {
		return fmt.Errorf("service.display_name must not be empty")
	}
	if c.Service.PruneInterval.Std() <= 0 {
		return fmt.Errorf("service.prune_interval must be positive")
	}
	if c.Service.PruneAfter.Std() <= 0 {
		return fmt.Errorf("service.prune_after must be positive")
	}
	if c.Replay.Count < 0 {
		return fmt.Errorf("replay.count must be >= 0")
	}
	if c.Replay.MaxAge.Std() < 0 {
		return fmt.Errorf("replay.max_age must be >= 0")
	}

	c.Admins = normalizeHashList(c.Admins)
	c.Mods = normalizeHashList(c.Mods)
	if err := validateHashes("admins", c.Admins); err != nil {
		return err
	}
	if err := validateHashes("mods", c.Mods); err != nil {
		return err
	}
	return nil
}

func normalizeHashList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, h := range in {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}

func validateHashes(field string, hashes []string) error {
	for _, h := range hashes {
		raw, err := hex.DecodeString(h)
		if err != nil {
			return fmt.Errorf("%s: %q is not valid hex: %w", field, h, err)
		}
		if len(raw) != identityHashLen {
			return fmt.Errorf("%s: %q must decode to %d bytes (got %d)", field, h, identityHashLen, len(raw))
		}
	}
	return nil
}

func ExpandPath(p string) (string, error) {
	if p == "" {
		return p, nil
	}
	if strings.HasPrefix(p, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		p = filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	return filepath.Clean(p), nil
}

// IsAdmin returns true if the lowercase hex hash is in the configured admins list.
func (c *Config) IsAdmin(hashHex string) bool {
	return contains(c.Admins, strings.ToLower(hashHex))
}

// IsMod returns true if the lowercase hex hash is in the configured mods list.
func (c *Config) IsMod(hashHex string) bool {
	return contains(c.Mods, strings.ToLower(hashHex))
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

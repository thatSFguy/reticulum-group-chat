package config

import (
	"encoding/base64"
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

// identityPrivateKeyLen is the on-disk Reticulum identity blob: 32-byte
// X25519 private key concatenated with 32-byte Ed25519 seed (SPEC §1.3).
// Duplicated here from rns.PrivateKeyLen to keep config validation
// independent of the rns package import.
const identityPrivateKeyLen = 64

type Config struct {
	Service    ServiceConfig     `toml:"service"`
	Interfaces []InterfaceConfig `toml:"interfaces"`
	Replay     ReplayConfig      `toml:"replay"`
	Admins     []string          `toml:"admins"`
	Mods       []string          `toml:"mods"`
}

type ServiceConfig struct {
	DisplayName  string `toml:"display_name"`
	IdentityPath string `toml:"identity_path"`

	// IdentityB64 is an optional base64-encoded backup of the 64-byte
	// Reticulum private key (X25519 priv 32 || Ed25519 seed 32). When
	// set, it takes precedence over IdentityPath — the on-disk file is
	// ignored and not written to. The field exists so an operator can
	// keep their identity inside the same config they back up before a
	// reinstall, instead of remembering to also copy the binary
	// identity file.
	//
	// Treat as a SECRET — anyone with this string is your service.
	// Generated automatically on first run alongside the binary
	// identity file (see <state_dir>/identity.b64.txt) and logged with
	// instructions; subsequent runs read the file and leave the config
	// untouched until the operator chooses to copy the b64 value in.
	IdentityB64 string `toml:"identity_b64"`

	StatePath        string   `toml:"state_path"`
	HistoryPath      string   `toml:"history_path"`
	LogPath          string   `toml:"log_path"`
	PruneAfter       Duration `toml:"prune_after"`
	PruneInterval    Duration `toml:"prune_interval"`
	AnnounceInterval Duration `toml:"announce_interval"`

	// MaxInboundChars caps how many UTF-8 characters an inbound message
	// from a roster member may contain. Anything longer is rejected with
	// a polite reply to the sender — the message is not forwarded, not
	// added to history, and the sender is not joined to the roster on
	// the back of an oversized first message. This is a spam-prevention
	// policy limit, separate from the wire-format size cap.
	// 0 = unlimited (not recommended). Default: 500.
	MaxInboundChars int `toml:"max_inbound_chars"`

	// MaxMembers caps the size of the roster. /join attempts past this
	// limit are refused with a polite "the chat is full" reply; the
	// would-be joiner is not added. Existing members and paused members
	// both count toward the limit. 0 = unlimited (default).
	MaxMembers int `toml:"max_members"`

	// ForwardAttachments controls whether non-text LXMF fields
	// (FIELD_IMAGE = 6, FIELD_FILE_ATTACHMENTS = 5, FIELD_AUDIO = 7, …)
	// are passed through to roster recipients alongside the text body.
	// When false, every inbound non-empty fields map is dropped silently
	// and only the text body is forwarded. Default true.
	ForwardAttachments bool `toml:"forward_attachments"`

	// MaxAttachmentBytes caps the msgpack-encoded size of any single
	// allowed field value. Oversized fields are dropped (text body still
	// forwards, with a "[image not forwarded: NNN B > LIMIT B]" suffix);
	// the whole message is not lost. 0 disables the cap (not
	// recommended on LoRa). Default 32768 — matches Sideband's typical
	// 20–30 KB output and the mobile app's defensive inbound cap.
	MaxAttachmentBytes int `toml:"max_attachment_bytes"`

	// ForwardedFields is the allowlist of LXMF field keys that pass
	// through forwarding. Anything not in this list is dropped even when
	// ForwardAttachments=true — defense against a misbehaving client
	// stuffing weird keys, and an operator opt-in for new field types
	// (FIELD_FILE_ATTACHMENTS = 5, FIELD_AUDIO = 7, etc.) once those
	// clients shake out. Default [6] (FIELD_IMAGE only).
	ForwardedFields []int `toml:"forwarded_fields"`
}

// InterfaceConfig declares a single Reticulum I/O interface. Currently
// only "tcp_client" is supported (dials a TCPServerInterface peer and
// exchanges HDLC-framed packets).
type InterfaceConfig struct {
	Type    string   `toml:"type"`
	Addr    string   `toml:"addr"`
	Timeout Duration `toml:"timeout"`
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
			DisplayName:      "Group Chat - send /join",
			IdentityPath:     "~/.fwdsvc/identity",
			StatePath:        "~/.fwdsvc/state.json",
			HistoryPath:      "~/.fwdsvc/history.json",
			PruneAfter:       Duration(4 * 7 * 24 * time.Hour),
			PruneInterval:    Duration(1 * time.Hour),
			AnnounceInterval:   Duration(10 * time.Minute),
			MaxInboundChars:    500,
			ForwardAttachments: true,
			MaxAttachmentBytes: 32768,
			ForwardedFields:    []int{6},
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
		&c.Service.LogPath,
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
	if c.Service.AnnounceInterval.Std() <= 0 {
		return fmt.Errorf("service.announce_interval must be positive")
	}
	if c.Service.MaxInboundChars < 0 {
		return fmt.Errorf("service.max_inbound_chars must be >= 0")
	}
	if c.Service.MaxMembers < 0 {
		return fmt.Errorf("service.max_members must be >= 0")
	}
	if c.Service.MaxAttachmentBytes < 0 {
		return fmt.Errorf("service.max_attachment_bytes must be >= 0")
	}
	for i, k := range c.Service.ForwardedFields {
		if k < 0 {
			return fmt.Errorf("service.forwarded_fields[%d]: field key must be >= 0", i)
		}
	}
	if s := strings.TrimSpace(c.Service.IdentityB64); s != "" {
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return fmt.Errorf("service.identity_b64: not valid base64: %w", err)
		}
		if len(raw) != identityPrivateKeyLen {
			return fmt.Errorf("service.identity_b64: must decode to %d bytes (got %d)",
				identityPrivateKeyLen, len(raw))
		}
		c.Service.IdentityB64 = s
	}
	for i, iface := range c.Interfaces {
		if iface.Type != "tcp_client" {
			return fmt.Errorf("interfaces[%d]: only tcp_client is supported, got %q", i, iface.Type)
		}
		if strings.TrimSpace(iface.Addr) == "" {
			return fmt.Errorf("interfaces[%d]: addr is required", i)
		}
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

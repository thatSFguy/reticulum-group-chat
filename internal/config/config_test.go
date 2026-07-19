package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// validServiceConfig is the minimum ServiceConfig that passes normalize();
// per-test code adds the field under test.
func validServiceConfig() ServiceConfig {
	return ServiceConfig{
		DisplayName:      "x",
		IdentityPath:     "/tmp/id",
		StatePath:        "/tmp/st",
		HistoryPath:      "/tmp/hi",
		PruneAfter:       Duration(time.Hour),
		PruneInterval:    Duration(time.Minute),
		AnnounceInterval: Duration(time.Minute),
		MaxInboundChars:  500,
	}
}

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
			DisplayName:      "x",
			IdentityPath:     "/tmp/id",
			StatePath:        "/tmp/st",
			HistoryPath:      "/tmp/hi",
			PruneAfter:       Duration(time.Hour),
			PruneInterval:    Duration(time.Minute),
			AnnounceInterval: Duration(time.Minute),
			MaxInboundChars:  500,
		},
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
			DisplayName:      "x",
			IdentityPath:     "/tmp/id",
			StatePath:        "/tmp/st",
			HistoryPath:      "/tmp/hi",
			PruneAfter:       Duration(time.Hour),
			PruneInterval:    Duration(time.Minute),
			AnnounceInterval: Duration(time.Minute),
			MaxInboundChars:  500,
		},
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

func TestIdentityB64ValidatesLength(t *testing.T) {
	// Valid 64-byte identity → accepted.
	raw := make([]byte, identityPrivateKeyLen)
	for i := range raw {
		raw[i] = byte(i)
	}
	cfg := &Config{Service: validServiceConfig()}
	cfg.Service.IdentityB64 = base64.StdEncoding.EncodeToString(raw)
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize with valid identity_b64: %v", err)
	}

	// Wrong length → rejected with a useful error.
	cfg2 := &Config{Service: validServiceConfig()}
	cfg2.Service.IdentityB64 = base64.StdEncoding.EncodeToString(make([]byte, 32))
	err := cfg2.normalize()
	if err == nil {
		t.Fatal("normalize: expected error for 32-byte identity_b64")
	}
	if !strings.Contains(err.Error(), "64 bytes") {
		t.Errorf("error should mention 64 bytes, got: %v", err)
	}

	// Invalid base64 → rejected.
	cfg3 := &Config{Service: validServiceConfig()}
	cfg3.Service.IdentityB64 = "not!valid!base64!"
	if err := cfg3.normalize(); err == nil {
		t.Fatal("normalize: expected error for non-base64 identity_b64")
	}
}

func TestIdentityB64EmptyIsAllowed(t *testing.T) {
	// Empty/missing field is the default and must not error — file
	// path takes over in service.loadOrCreateIdentity.
	cfg := &Config{Service: validServiceConfig()}
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize with empty identity_b64: %v", err)
	}
}

func TestAttachmentConfigDefaults(t *testing.T) {
	c := defaults()
	if !c.Service.ForwardAttachments {
		t.Error("ForwardAttachments default should be true")
	}
	if c.Service.MaxAttachmentBytes != 1000*1024 {
		t.Errorf("MaxAttachmentBytes default = %d, want %d", c.Service.MaxAttachmentBytes, 1000*1024)
	}
	// Default allowlist: FIELD_IMAGE plus the upstream LXMF 1.0.0
	// message-meta fields — reply-to 0x30 (48) + quote 0x31 (49),
	// reaction 0x40 (64), comment 0x41 (65), continuation 0x42 (66).
	// See issue #8.
	wantFields := map[int]bool{6: true, 48: true, 49: true, 64: true, 65: true, 66: true}
	if len(c.Service.ForwardedFields) != len(wantFields) {
		t.Errorf("ForwardedFields default = %v, want keys %v",
			c.Service.ForwardedFields, wantFields)
	}
	for _, k := range c.Service.ForwardedFields {
		if !wantFields[k] {
			t.Errorf("unexpected key %d in default ForwardedFields = %v",
				k, c.Service.ForwardedFields)
		}
	}
}

func TestNormalizeRejectsNegativeAttachmentBytes(t *testing.T) {
	cfg := &Config{Service: validServiceConfig()}
	cfg.Service.MaxAttachmentBytes = -1
	if err := cfg.normalize(); err == nil {
		t.Fatal("expected normalize to reject negative max_attachment_bytes")
	}
}

func TestNormalizeRejectsNegativeForwardedFieldKey(t *testing.T) {
	cfg := &Config{Service: validServiceConfig()}
	cfg.Service.ForwardedFields = []int{6, -1}
	if err := cfg.normalize(); err == nil {
		t.Fatal("expected normalize to reject negative forwarded_fields entry")
	}
}

func TestDedupWindowDefaultAndParse(t *testing.T) {
	if got := defaults().Service.DedupWindow.Std(); got != time.Hour {
		t.Errorf("DedupWindow default = %s, want 1h", got)
	}
	// Full Load exercises the `toml:"dedup_window"` tag binding (a tag typo
	// would silently leave the default, so assert on a non-default value).
	dir := t.TempDir()
	path := filepath.Join(dir, "c.toml")
	if err := os.WriteFile(path, []byte("[service]\ndisplay_name = \"x\"\ndedup_window = \"30m\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := c.Service.DedupWindow.Std(); got != 30*time.Minute {
		t.Errorf("DedupWindow parsed = %s, want 30m", got)
	}
}

func TestNormalizeRejectsNegativeDedupWindow(t *testing.T) {
	cfg := &Config{Service: validServiceConfig()}
	cfg.Service.DedupWindow = Duration(-time.Minute)
	if err := cfg.normalize(); err == nil {
		t.Fatal("expected normalize to reject negative dedup_window")
	}
}

func TestLockedDefaultAndParse(t *testing.T) {
	// Default: open chat.
	if defaults().Service.Locked {
		t.Error("Locked default should be false (open chat)")
	}

	dir := t.TempDir()

	// `locked = true` under [service] binds (exercises the toml:"locked" tag).
	good := filepath.Join(dir, "good.toml")
	if err := os.WriteFile(good, []byte("[service]\ndisplay_name = \"x\"\nlocked = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(good)
	if err != nil {
		t.Fatalf("Load good: %v", err)
	}
	if !c.Service.Locked {
		t.Error("locked = true under [service] should parse to Service.Locked == true")
	}

	// The operator footgun: `locked` ABOVE [service] is a top-level key TOML
	// silently ignores, so it must NOT bind (and must not error). This guards
	// the "I set locked=true but /join still works" support case.
	bad := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(bad, []byte("locked = true\n[service]\ndisplay_name = \"x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	badCfg, err := Load(bad)
	if err != nil {
		t.Fatalf("Load bad: %v", err)
	}
	if badCfg.Service.Locked {
		t.Error("locked placed above [service] is a top-level key and must NOT bind to Service.Locked")
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

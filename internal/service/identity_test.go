package service

import (
	"bytes"
	"encoding/base64"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/thatSFguy/reticulum-group-chat/internal/rns"
)

// quietLogger is a *log.Logger that drops every line. Used so test
// runs aren't polluted with the BACKUP: lines we emit on first
// generation.
func quietLogger() *log.Logger { return log.New(io.Discard, "", 0) }

func TestLoadOrCreateIdentityPrefersConfigB64OverFile(t *testing.T) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity")

	// Pre-create a DIFFERENT identity at identityPath so we can prove
	// it's NOT used when identity_b64 is set.
	fileID, err := rns.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (file): %v", err)
	}
	if err := fileID.Save(identityPath); err != nil {
		t.Fatalf("Save (file): %v", err)
	}

	// Generate a separate identity for the config side.
	configID, err := rns.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (config): %v", err)
	}
	configB64 := base64.StdEncoding.EncodeToString(configID.PrivateKey())

	loaded, err := loadOrCreateIdentity(configB64, identityPath, quietLogger())
	if err != nil {
		t.Fatalf("loadOrCreateIdentity: %v", err)
	}
	if !bytes.Equal(loaded.PrivateKey(), configID.PrivateKey()) {
		t.Errorf("loaded identity does not match config_b64; file took precedence")
	}
	if bytes.Equal(loaded.PrivateKey(), fileID.PrivateKey()) {
		t.Errorf("loaded the FILE identity even though config_b64 was set")
	}
}

func TestLoadOrCreateIdentityFallsBackToFile(t *testing.T) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity")

	original, err := rns.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	if err := original.Save(identityPath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := loadOrCreateIdentity("", identityPath, quietLogger())
	if err != nil {
		t.Fatalf("loadOrCreateIdentity: %v", err)
	}
	if !bytes.Equal(loaded.PrivateKey(), original.PrivateKey()) {
		t.Errorf("loaded identity does not match the file we wrote")
	}
}

func TestLoadOrCreateIdentityGeneratesAndWritesBackup(t *testing.T) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity")
	backupPath := identityPath + ".b64.txt"

	id, err := loadOrCreateIdentity("", identityPath, quietLogger())
	if err != nil {
		t.Fatalf("loadOrCreateIdentity: %v", err)
	}

	// Binary identity file written.
	if _, err := os.Stat(identityPath); err != nil {
		t.Fatalf("identity file not created: %v", err)
	}
	// Backup file written, mode 0600, contents match the b64 of the identity.
	info, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("backup file not created: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		// On Windows file mode bits don't fully apply; only assert on
		// Unix-y systems where the os returns meaningful perms.
		if !isWindowsModeFudgey(mode) {
			t.Errorf("backup file mode = %v, want 0o600", mode)
		}
	}
	content, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	want := base64.StdEncoding.EncodeToString(id.PrivateKey()) + "\n"
	if string(content) != want {
		t.Errorf("backup content does not match generated identity")
	}

	// And calling loadOrCreateIdentity again with the same path returns
	// the same identity (file path branch).
	id2, err := loadOrCreateIdentity("", identityPath, quietLogger())
	if err != nil {
		t.Fatalf("second loadOrCreateIdentity: %v", err)
	}
	if !bytes.Equal(id.PrivateKey(), id2.PrivateKey()) {
		t.Errorf("second load returned a different identity")
	}
}

func TestLoadOrCreateIdentityRejectsBadB64(t *testing.T) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity")

	// Valid base64, wrong length.
	short := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if _, err := loadOrCreateIdentity(short, identityPath, quietLogger()); err == nil {
		t.Errorf("expected error for short identity_b64")
	}

	// Not even base64.
	if _, err := loadOrCreateIdentity("not!base64!", identityPath, quietLogger()); err == nil {
		t.Errorf("expected error for non-base64 identity_b64")
	}
}

// isWindowsModeFudgey returns true when the permission bits look like
// Windows-style "no perm bits applied" so we can skip strict 0600
// assertions on that platform. Linux/macOS file modes will show 0o600
// exactly after Chmod.
func isWindowsModeFudgey(m os.FileMode) bool {
	// Windows typically reports either 0666 or 0444 depending on the
	// read-only attribute — neither matches Unix 0600. Treat any
	// world-readable bits as "Windows-style fudge."
	return m&0o007 != 0 || m&0o070 != 0
}

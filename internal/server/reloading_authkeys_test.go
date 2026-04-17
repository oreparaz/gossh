package server_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oscar/gossh/internal/hostkey"
	"github.com/oscar/gossh/internal/server"
)

// TestReloadingAuthorizedKeys verifies that a key revocation takes
// effect immediately — specifically that replacing the file with an
// empty one stops authenticating the previously-accepted key.
func TestReloadingAuthorizedKeys(t *testing.T) {
	dir := t.TempDir()
	userPath := filepath.Join(dir, "u")
	if _, err := hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "u"); err != nil {
		t.Fatal(err)
	}
	pub, _ := os.ReadFile(userPath + ".pub")
	ak := filepath.Join(dir, "ak")
	if err := os.WriteFile(ak, pub, 0o600); err != nil {
		t.Fatal(err)
	}

	lookup := server.ReloadingAuthorizedKeys(ak)

	entries1, err := lookup("anyone")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries1) != 1 {
		t.Fatalf("first lookup: %d entries, want 1", len(entries1))
	}

	// Overwrite with an empty file. Ensure mtime ticks even on fast
	// filesystems.
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(ak, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	entries2, err := lookup("anyone")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries2) != 0 {
		t.Fatalf("after revoke: %d entries, want 0", len(entries2))
	}
}

// TestReloadingAuthorizedKeysRefusesMalformed verifies that putting a
// broken line in the file surfaces the parse error — we do NOT fall
// back to the previously-cached good copy, because silently ignoring
// an admin's intended change could be a security footgun.
func TestReloadingAuthorizedKeysRefusesMalformed(t *testing.T) {
	dir := t.TempDir()
	userPath := filepath.Join(dir, "u")
	hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "u")
	pub, _ := os.ReadFile(userPath + ".pub")
	ak := filepath.Join(dir, "ak")
	os.WriteFile(ak, pub, 0o600)

	lookup := server.ReloadingAuthorizedKeys(ak)
	_, err := lookup("anyone")
	if err != nil {
		t.Fatalf("initial: %v", err)
	}

	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(ak, []byte("cmmand=\"foo\" "+string(pub)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = lookup("anyone")
	if err == nil {
		t.Fatal("expected error from typo'd option")
	}
	if !strings.Contains(err.Error(), "unknown authorized_keys option") {
		t.Fatalf("expected strict option rejection; got %v", err)
	}
	// Silence unused ssh import.
	_ = ssh.Password
}

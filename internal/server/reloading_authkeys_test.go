package server_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oreparaz/gossh/internal/hostkey"
	"github.com/oreparaz/gossh/internal/server"
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

// TestReloadingAuthorizedKeysRevocationE2E boots gosshd with the
// reloading AK function and verifies that removing the key from the
// file mid-run rejects the next connection. This is the realistic
// deployment scenario — admin revokes a key, expects it to take
// effect immediately.
func TestReloadingAuthorizedKeysRevocationE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dir := t.TempDir()
	hk, _ := hostkey.LoadOrGenerate(filepath.Join(dir, "h"), hostkey.Ed25519, 0, "h")
	userPath := filepath.Join(dir, "u")
	hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "u")
	pub, _ := os.ReadFile(userPath + ".pub")
	ak := filepath.Join(dir, "ak")
	if err := os.WriteFile(ak, pub, 0o600); err != nil {
		t.Fatal(err)
	}

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	_, portStr, _ := net.SplitHostPort(l.Addr().String())

	s, _ := server.New(server.Config{
		HostKeys:       []ssh.Signer{hk.Signer},
		AuthorizedKeys: server.ReloadingAuthorizedKeys(ak),
		Shell:          "/bin/bash",
		AllowExec:      true,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve(ctx, l) }()
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(50 * time.Millisecond)

	kh := filepath.Join(dir, "kh")
	os.WriteFile(kh, []byte(fmt.Sprintf("[127.0.0.1]:%s %s", portStr, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))), 0o600)

	h := &testHarness{Host: "127.0.0.1", Port: portStr, KnownHosts: kh, UserKeyPath: userPath}

	// First attempt: should succeed.
	var out1, err1 bytes.Buffer
	cmd1 := h.sshCmd(t, nil, "echo pre-revoke")
	cmd1.Stdout = &out1
	cmd1.Stderr = &err1
	if err := cmd1.Run(); err != nil {
		t.Fatalf("first ssh: %v\n%s", err, err1.String())
	}
	if !strings.Contains(out1.String(), "pre-revoke") {
		t.Fatalf("stdout=%q", out1.String())
	}

	// Revoke the key.
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(ak, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}

	// Second attempt: must fail.
	cmd2 := h.sshCmd(t, nil, "echo post-revoke")
	if err := cmd2.Run(); err == nil {
		t.Fatalf("expected ssh to fail after revocation")
	}
}

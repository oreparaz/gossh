package server_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oreparaz/gossh/internal/authkeys"
	"github.com/oreparaz/gossh/internal/hostkey"
	"github.com/oreparaz/gossh/internal/server"
)

// TestRefusesLegacyKEX verifies that a client offering only
// diffie-hellman-group14-sha1 fails to negotiate with gosshd.
func TestRefusesLegacyKEX(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dir := t.TempDir()
	hkPath := filepath.Join(dir, "h")
	hk, err := hostkey.LoadOrGenerate(hkPath, hostkey.Ed25519, 0, "h")
	if err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(dir, "u")
	if _, err := hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "u"); err != nil {
		t.Fatal(err)
	}
	pub, _ := os.ReadFile(userPath + ".pub")
	ak := filepath.Join(dir, "ak")
	os.WriteFile(ak, pub, 0o600)
	entries, _ := authkeys.ParseFile(ak)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s, _ := server.New(server.Config{
		HostKeys:       []ssh.Signer{hk.Signer},
		AuthorizedKeys: server.StaticAuthorizedKeys(entries),
		Shell:          "/bin/bash",
		AllowExec:      true,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	time.Sleep(50 * time.Millisecond)

	uk, err := hostkey.Load(userPath)
	if err != nil {
		t.Fatal(err)
	}
	// Client offers only a legacy KEX that gosshd must refuse.
	cfg := &ssh.ClientConfig{
		User:            "u",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(uk.Signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec — test only
	}
	cfg.KeyExchanges = []string{"diffie-hellman-group14-sha1"}

	_, err = ssh.Dial("tcp", l.Addr().String(), cfg)
	if err == nil {
		t.Fatal("expected algorithm negotiation failure")
	}
	// The error wording comes from the ssh library; we just want to see
	// a negotiation failure, not e.g. an auth failure.
	if !strings.Contains(strings.ToLower(err.Error()), "algorithm") &&
		!strings.Contains(strings.ToLower(err.Error()), "key exchange") &&
		!strings.Contains(strings.ToLower(err.Error()), "no common") &&
		!strings.Contains(strings.ToLower(err.Error()), "ssh: handshake") {
		t.Fatalf("unexpected error type: %v", err)
	}
}

// TestRefusesLegacyCipher is the same but for an AES-CBC-only client.
func TestRefusesLegacyCipher(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dir := t.TempDir()
	hkPath := filepath.Join(dir, "h")
	hk, _ := hostkey.LoadOrGenerate(hkPath, hostkey.Ed25519, 0, "h")
	userPath := filepath.Join(dir, "u")
	hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "u")
	pub, _ := os.ReadFile(userPath + ".pub")
	ak := filepath.Join(dir, "ak")
	os.WriteFile(ak, pub, 0o600)
	entries, _ := authkeys.ParseFile(ak)

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	s, _ := server.New(server.Config{
		HostKeys:       []ssh.Signer{hk.Signer},
		AuthorizedKeys: server.StaticAuthorizedKeys(entries),
		Shell:          "/bin/bash",
		AllowExec:      true,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	time.Sleep(50 * time.Millisecond)

	uk, _ := hostkey.Load(userPath)
	cfg := &ssh.ClientConfig{
		User:            "u",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(uk.Signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec — test only
	}
	cfg.Ciphers = []string{"aes128-cbc"}

	if _, err := ssh.Dial("tcp", l.Addr().String(), cfg); err == nil {
		t.Fatal("expected cipher negotiation failure")
	}
}

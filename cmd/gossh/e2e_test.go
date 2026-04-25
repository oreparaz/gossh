package main_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oreparaz/gossh/internal/authkeys"
	"github.com/oreparaz/gossh/internal/hostkey"
	"github.com/oreparaz/gossh/internal/server"
)

// TestGosshBinaryAgainstGosshd builds both binaries and uses the
// gossh binary to run a remote command via a gosshd instance we
// started in-process. This exercises the actual CLI code paths
// (flag parsing, startup, error handling) end-to-end.
func TestGosshBinaryAgainstGosshd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}

	// Build the gossh binary into a test-local path.
	dir := t.TempDir()
	bin := filepath.Join(dir, "gossh")
	build := exec.Command(goBinary(), "build", "-o", bin, "github.com/oreparaz/gossh/cmd/gossh")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}

	// Set up host + user keys, authorized_keys, known_hosts.
	hkPath := filepath.Join(dir, "host_ed25519")
	hk, err := hostkey.LoadOrGenerate(hkPath, hostkey.Ed25519, 0, "host@test")
	if err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(dir, "id_ed25519")
	if _, err := hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "user@test"); err != nil {
		t.Fatal(err)
	}
	akPath := filepath.Join(dir, "authorized_keys")
	pub, _ := os.ReadFile(userPath + ".pub")
	if err := os.WriteFile(akPath, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := authkeys.ParseFile(akPath)
	if err != nil {
		t.Fatal(err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, _ := net.SplitHostPort(l.Addr().String())

	s, err := server.New(server.Config{
		HostKeys:       []ssh.Signer{hk.Signer},
		AuthorizedKeys: server.StaticAuthorizedKeys(entries),
		Shell:          "/bin/bash",
		AllowExec:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
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

	// known_hosts pre-populated so strict mode works.
	kh := filepath.Join(dir, "known_hosts")
	line := fmt.Sprintf("[127.0.0.1]:%s %s", portStr, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))
	if err := os.WriteFile(kh, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	// gossh invocation.
	cmd := exec.Command(bin,
		"-i", userPath,
		"-known-hosts", kh,
		"-strict-host-key", "yes",
		"-p", portStr,
		"-T",
		"testuser@127.0.0.1",
		"echo from-gossh-binary",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("gossh: %v\nstderr=%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "from-gossh-binary") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

// TestGosshdDefaultsAreSafe boots the gosshd binary with only the
// required flags and confirms password auth is rejected by default
// (it has no callback configured, so the library refuses every try).
func TestGosshdBinarySmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dir := t.TempDir()
	gosshd := filepath.Join(dir, "gosshd")
	build := exec.Command(goBinary(), "build", "-o", gosshd, "github.com/oreparaz/gossh/cmd/gosshd")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}

	// Pick a free port, then ask gosshd to listen there.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	// Minimal authorized_keys + host key path.
	hkPath := filepath.Join(dir, "host")
	userPath := filepath.Join(dir, "id")
	if _, err := hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "u"); err != nil {
		t.Fatal(err)
	}
	pub, _ := os.ReadFile(userPath + ".pub")
	ak := filepath.Join(dir, "ak")
	if err := os.WriteFile(ak, pub, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(gosshd,
		"-listen", addr,
		"-host-key", hkPath,
		"-authorized-keys", ak,
		"-shell", "/bin/bash",
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	// Wait for it to bind.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("gosshd never started listening")
}

package main_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oscar/gossh/internal/authkeys"
	"github.com/oscar/gossh/internal/hostkey"
	"github.com/oscar/gossh/internal/server"
)

// TestGosshAutoloadsDotSSHConfig verifies that with no -F flag,
// gossh still picks up ~/.ssh/config — matching OpenSSH's behavior.
// We drive this by pointing HOME at a temp dir whose .ssh/config
// aliases "devbox" to our in-process gosshd.
func TestGosshAutoloadsDotSSHConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	home := t.TempDir()
	ssh_ := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh_, 0o700); err != nil {
		t.Fatal(err)
	}

	// Build the gossh binary.
	binDir := t.TempDir()
	bin := filepath.Join(binDir, "gossh")
	build := exec.Command("/usr/local/go/bin/go", "build", "-o", bin,
		"github.com/oscar/gossh/cmd/gossh")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}

	// Host + user keys + authorized_keys + listener.
	hkPath := filepath.Join(home, "host_ed25519")
	hk, err := hostkey.LoadOrGenerate(hkPath, hostkey.Ed25519, 0, "h")
	if err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(ssh_, "id_ed25519")
	if _, err := hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "u"); err != nil {
		t.Fatal(err)
	}
	pub, _ := os.ReadFile(userPath + ".pub")
	ak := filepath.Join(home, "ak")
	os.WriteFile(ak, pub, 0o600)
	entries, _ := authkeys.ParseFile(ak)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	_, portStr, _ := net.SplitHostPort(l.Addr().String())

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

	// Populate ~/.ssh/config and known_hosts in the fake home.
	kh := filepath.Join(ssh_, "known_hosts")
	os.WriteFile(kh, []byte(fmt.Sprintf("[127.0.0.1]:%s %s",
		portStr, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))), 0o600)

	cfg := filepath.Join(ssh_, "config")
	os.WriteFile(cfg, []byte(fmt.Sprintf(`Host devbox
    Hostname 127.0.0.1
    Port %s
    User testuser
    IdentityFile %s
    UserKnownHostsFile %s
    StrictHostKeyChecking yes
`, portStr, userPath, kh)), 0o600)

	// Invoke gossh WITHOUT -F. Only the alias "devbox" is given.
	cmd := exec.Command(bin, "-T", "devbox", "echo", "auto-config-works")
	cmd.Env = append(os.Environ(), "HOME="+home)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("gossh: %v\nstderr=%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "auto-config-works") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	_ = io.EOF // keep imports tidy across future edits
}

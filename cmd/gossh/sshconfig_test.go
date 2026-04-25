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

// TestGosshHonoursSSHConfig boots a gosshd, writes an ssh_config that
// aliases "short" to the in-process address, and confirms that
// `gossh -F <config> short cmd` works.
func TestGosshHonoursSSHConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dir := t.TempDir()
	gossh := filepath.Join(dir, "gossh")
	build := exec.Command("/usr/local/go/bin/go", "build", "-o", gossh, "github.com/oreparaz/gossh/cmd/gossh")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatal(err)
	}

	hkPath := filepath.Join(dir, "host")
	hk, err := hostkey.LoadOrGenerate(hkPath, hostkey.Ed25519, 0, "h")
	if err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(dir, "id")
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
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(50 * time.Millisecond)

	kh := filepath.Join(dir, "kh")
	os.WriteFile(kh, []byte(fmt.Sprintf("[127.0.0.1]:%s %s", portStr, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))), 0o600)

	cfg := filepath.Join(dir, "ssh_config")
	os.WriteFile(cfg, []byte(fmt.Sprintf(`Host short
    Hostname 127.0.0.1
    Port %s
    User testuser
    IdentityFile %s
    UserKnownHostsFile %s
    StrictHostKeyChecking yes
`, portStr, userPath, kh)), 0o600)

	cmd := exec.Command(gossh, "-F", cfg, "-T", "short", "echo", "via-config")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("gossh: %v\nstderr=%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "via-config") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

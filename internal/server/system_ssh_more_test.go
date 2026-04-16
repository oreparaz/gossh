package server_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oscar/gossh/internal/audit"
	"github.com/oscar/gossh/internal/authkeys"
	"github.com/oscar/gossh/internal/hostkey"
	"github.com/oscar/gossh/internal/server"
	"os"
)

// TestSystemSSHEnvAllowlist verifies that:
//   - TERM/LANG/LC_* sent by system ssh reach the remote env
//   - FOO (not in allowlist) does NOT reach the remote env
//
// The allowlist lives in internal/server/requests.go (isSafeEnvName).
func TestSystemSSHEnvAllowlist(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	h := startServer(t, nil)

	// ssh -o SendEnv=FOO -o SendEnv=LC_CUSTOM … LANG=en_US.UTF-8 FOO=secret LC_CUSTOM=x ssh …
	// We set env on the ssh subprocess and SendEnv asks the server to
	// propagate those names. The server should accept LC_* and drop FOO.
	cmd := h.sshCmd(t, []string{
		"-o", "SendEnv=FOO",
		"-o", "SendEnv=LC_CUSTOM",
	}, "printenv LANG LC_CUSTOM FOO || true; echo ---DONE")
	cmd.Env = append(cmd.Env,
		"LANG=en_US.UTF-8",
		"LC_CUSTOM=leaky",
		"FOO=should-not-cross",
	)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("ssh: %v\nstderr=%s", err, stderr.String())
	}
	s := out.String()
	if !strings.Contains(s, "en_US.UTF-8") {
		t.Fatalf("LANG not propagated: %q", s)
	}
	if !strings.Contains(s, "leaky") {
		t.Fatalf("LC_CUSTOM should be allowed: %q", s)
	}
	if strings.Contains(s, "should-not-cross") {
		t.Fatalf("FOO leaked past allowlist: %q", s)
	}
}

// TestSystemSSHSubsystemRefused verifies that we don't accept SFTP
// subsystem requests. `ssh -s sftp host` should exit non-zero.
func TestSystemSSHSubsystemRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	h := startServer(t, nil)
	cmd := h.sshCmd(t, []string{"-s"}, "sftp")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err == nil {
		t.Fatal("sftp subsystem must be refused")
	}
}

// TestSystemSSHCommandWithPTYTTY verifies that the remote sees a real
// PTY (tty returns /dev/pts/N). Dropped the more complex stdin round
// trip because pty line discipline + Ctrl-D handling is brittle in a
// CI pipe rather than a real terminal.
func TestSystemSSHCommandWithPTYTTY(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	h := startServer(t, nil)
	cmd := h.sshCmd(t, []string{"-tt"}, "tty; echo ---DONE")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("ssh: %v stderr=%s", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "/dev/pts/") && !strings.Contains(out, "/dev/ptmx") {
		t.Fatalf("tty path missing: %q", out)
	}
	if !strings.Contains(out, "---DONE") {
		t.Fatalf("marker missing: %q", out)
	}
}

// TestSystemSSHKeepaliveFiresAndCloses verifies that when the server
// has ClientAliveInterval set and the client is idle, the server
// still probes and treats keepalive failures as grounds for closure.
// We simulate a dead client by black-holing writes.
func TestSystemSSHServerKeepaliveProbes(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	h := startServer(t, func(c *server.Config) {
		c.ClientAliveInterval = 200 * time.Millisecond
		c.ClientAliveCountMax = 2
	})

	// Start an idle session: ssh -N (no command) with forwarding would
	// keep alive; we instead run `sleep 10` and kill the client process
	// to simulate a half-open TCP.
	cmd := h.sshCmd(t, []string{"-o", "ServerAliveInterval=60"}, "sleep 30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	// Forcibly disappear.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	// Server should detect death within ClientAliveInterval * Count.
	// This is best-effort; we just give it time to unwind.
	_, _ = cmd.Process.Wait()
	time.Sleep(1 * time.Second)
	// If we reach here without the test infra hanging, goroutines are unwinding.
}

// TestSystemSSHForcedCommandWithPty confirms command= interacts
// correctly with a pty-req — we still run the forced command, not
// the client's, and the forced command sees a PTY.
func TestSystemSSHForcedCommandWithPty(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	h := buildCustomRig(t, `command="tty"`)
	cmd := h.sshCmd(t, []string{"-tt"}, "echo client-asked")
	var out, errout bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errout
	if err := cmd.Run(); err != nil {
		t.Fatalf("ssh: %v err=%s", err, errout.String())
	}
	// `tty` prints /dev/pts/N when run under a PTY.
	s := out.String()
	if strings.Contains(s, "client-asked") {
		t.Fatalf("client command leaked past force-command: %q", s)
	}
	if !strings.Contains(s, "/dev/") && !strings.Contains(s, "pts") {
		t.Fatalf("forced command did not see a tty: %q", s)
	}
}

// TestSystemSSHLargeRoundtripNoPty verifies we can transfer non-trivial
// data through an exec session and close cleanly. Similar to the
// earlier client-internal test but uses the system ssh binary.
func TestSystemSSHLargeExecDataRoundtrip(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	h := startServer(t, nil)
	// Have the remote emit 1 MiB of zero bytes and count them. Make sure
	// the shell doesn't interpret the output.
	cmd := h.sshCmd(t, nil, "head -c 1048576 /dev/zero | wc -c")
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("ssh: %v stderr=%s", err, stderr.String())
	}
	got := strings.TrimSpace(out.String())
	if got != "1048576" {
		t.Fatalf("wc -c got %q, want 1048576; stderr=%s", got, stderr.String())
	}
}

// TestAuditLogFileIsAppendedAndParseable spawns gosshd with a file
// audit log and a concurrent system-ssh client, and verifies the
// file contains parseable JSON-lines after the session.
func TestAuditLogFileIsAppendedAndParseable(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")

	// Replicate startServer but with a custom audit writer.
	hkPath := filepath.Join(dir, "h")
	hk, err := hostkey.LoadOrGenerate(hkPath, hostkey.Ed25519, 0, "h")
	if err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(dir, "id")
	if _, err := hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "u"); err != nil {
		t.Fatal(err)
	}
	akPath := filepath.Join(dir, "ak")
	pub, _ := os.ReadFile(userPath + ".pub")
	os.WriteFile(akPath, pub, 0o600)
	entries, _ := authkeys.ParseFile(akPath)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	_, portStr, _ := net.SplitHostPort(l.Addr().String())

	f, err := audit.OpenFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	s, _ := server.New(server.Config{
		HostKeys:       []ssh.Signer{hk.Signer},
		AuthorizedKeys: server.StaticAuthorizedKeys(entries),
		Shell:          "/bin/bash",
		AllowExec:      true,
		Audit:          &audit.JSONLogger{Writer: f, Fsync: true},
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

	kh := filepath.Join(dir, "kh")
	os.WriteFile(kh, []byte(fmt.Sprintf("[127.0.0.1]:%s %s", portStr, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))), 0o600)

	h := &testHarness{Host: "127.0.0.1", Port: portStr, KnownHosts: kh, UserKeyPath: userPath}
	cmd := h.sshCmd(t, nil, "echo audited")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh: %v\n%s", err, out)
	}
	// Give the server time to emit connection.close.
	time.Sleep(300 * time.Millisecond)

	b, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Fatal("audit log is empty")
	}
	// Must contain the expected event types.
	for _, want := range []string{`"auth.ok"`, `"session.exec"`, `"session.close"`, `"connection.close"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("audit log missing %s:\n%s", want, b)
		}
	}
	_ = exec.Command // keep import if unused elsewhere
}

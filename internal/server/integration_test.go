package server_test

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

// testHarness spins up a gosshd on a random port with a fresh host key
// and a single ed25519 user key. It returns the connection parameters
// the test should use.
type testHarness struct {
	Addr        string
	Host        string
	Port        string
	UserKeyPath string
	UserKeyPub  string
	KnownHosts  string
	cancel      context.CancelFunc
	done        chan struct{}
}

func startServer(t *testing.T, cfgMut func(*server.Config)) *testHarness {
	t.Helper()
	dir := t.TempDir()

	// Host key.
	hkPath := filepath.Join(dir, "host_ed25519")
	hk, err := hostkey.LoadOrGenerate(hkPath, hostkey.Ed25519, 0, "host@test")
	if err != nil {
		t.Fatal(err)
	}

	// User key.
	userPath := filepath.Join(dir, "id_ed25519")
	if _, err := hostkey.LoadOrGenerate(userPath, hostkey.Ed25519, 0, "user@test"); err != nil {
		t.Fatal(err)
	}

	// authorized_keys.
	akPath := filepath.Join(dir, "authorized_keys")
	pubBytes, _ := os.ReadFile(userPath + ".pub")
	if err := os.WriteFile(akPath, pubBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := authkeys.ParseFile(akPath)
	if err != nil {
		t.Fatal(err)
	}

	// known_hosts pre-populated with the host's public key so the
	// system ssh client never needs to prompt.
	khPath := filepath.Join(dir, "known_hosts")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	hostPubLine := fmt.Sprintf("[127.0.0.1]:%s %s", port, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))
	if err := os.WriteFile(khPath, []byte(hostPubLine), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := server.Config{
		HostKeys:       []ssh.Signer{hk.Signer},
		AuthorizedKeys: server.StaticAuthorizedKeys(entries),
		Shell:          "/bin/bash",
		AllowExec:      true,
		AllowPTY:       true,
		MaxAuthTries:   3,
	}
	if cfgMut != nil {
		cfgMut(&cfg)
	}
	s, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Serve(ctx, l)
	}()
	// Allow the server goroutine to reach Accept.
	time.Sleep(50 * time.Millisecond)

	h := &testHarness{
		Addr:        l.Addr().String(),
		Host:        "127.0.0.1",
		Port:        port,
		UserKeyPath: userPath,
		UserKeyPub:  userPath + ".pub",
		KnownHosts:  khPath,
		cancel:      cancel,
		done:        done,
	}
	t.Cleanup(func() {
		h.cancel()
		select {
		case <-h.done:
		case <-time.After(2 * time.Second):
		}
	})
	return h
}

// requireSSHClient skips the test if the system ssh binary is missing.
func requireSSHClient(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("system ssh not available")
	}
	return p
}

// sshCmd builds an ssh command that targets the harness with the
// generated user key and the pre-populated known_hosts file.
func (h *testHarness) sshCmd(t *testing.T, extraArgs []string, remoteCmd ...string) *exec.Cmd {
	t.Helper()
	sshBin := requireSSHClient(t)
	base := []string{
		"-i", h.UserKeyPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "UserKnownHostsFile=" + h.KnownHosts,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
		"-p", h.Port,
	}
	args := append(base, extraArgs...)
	args = append(args, "testuser@"+h.Host)
	args = append(args, remoteCmd...)
	return exec.Command(sshBin, args...)
}

func TestExecEchoInteropWithSystemSSH(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	h := startServer(t, nil)

	var stdout, stderr bytes.Buffer
	cmd := h.sshCmd(t, nil, "echo", "hello from gosshd")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("ssh exec failed: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != "hello from gosshd" {
		t.Fatalf("stdout = %q, want %q (stderr=%s)", got, "hello from gosshd", stderr.String())
	}
}

func TestExecExitCodePropagates(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	h := startServer(t, nil)
	cmd := h.sshCmd(t, nil, "exit", "42")
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit")
	}
	ee, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("err type %T", err)
	}
	if ee.ExitCode() != 42 {
		t.Fatalf("exit code = %d, want 42", ee.ExitCode())
	}
}

func TestExecStderrRouted(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	h := startServer(t, nil)

	var stdout, stderr bytes.Buffer
	cmd := h.sshCmd(t, nil, "echo to-stdout; echo to-stderr 1>&2")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("ssh: %v\n%s", err, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "to-stdout" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "to-stderr") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestUnauthorizedKeyRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	h := startServer(t, nil)

	// Generate a different user key that is NOT in authorized_keys.
	dir := t.TempDir()
	otherPath := filepath.Join(dir, "id_ed25519")
	if _, err := hostkey.LoadOrGenerate(otherPath, hostkey.Ed25519, 0, "other"); err != nil {
		t.Fatal(err)
	}

	sshBin := requireSSHClient(t)
	cmd := exec.Command(sshBin,
		"-i", otherPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "UserKnownHostsFile="+h.KnownHosts,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
		"-p", h.Port,
		"testuser@127.0.0.1",
		"echo", "should-not-run",
	)
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err == nil {
		t.Fatal("expected auth failure")
	}
}

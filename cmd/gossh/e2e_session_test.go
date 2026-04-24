package main_test

// End-to-end regression test for the combination of:
//   - recursive SCP (scp -r)
//   - ProxyCommand (tunnel the SSH transport through a shell command)
//   - Interactive/stateful session work (persistent tmux server, env,
//     send-keys, capture-pane) across separate gossh connections.
//
// All client-side work goes through the built gossh / gossh-scp
// binaries so CLI flag plumbing and ssh_config handling are covered.
// Server-side is the in-process server package — same wire protocol
// as the built gosshd, but avoids a second build.
//
// Skipped under -short (these are ~5 seconds of real I/O) and when
// nc or tmux are not installed.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
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

type e2eRig struct {
	port      int
	gossh     string
	gosshSCP  string
	sshConfig string
	home      string // test's fake HOME
	knownHost string
	idFile    string
}

// setupE2E builds both client binaries, starts an in-process gosshd,
// and writes ssh_config + known_hosts pointing at it. The ssh_config
// "devbox" alias uses ProxyCommand `nc -q0 %h %p`, so every test
// subcase below exercises the proxy-command path.
func setupE2E(t *testing.T) *e2eRig {
	t.Helper()
	if _, err := exec.LookPath("nc"); err != nil {
		t.Skip("nc not installed — ProxyCommand tests need netcat")
	}

	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}

	binDir := t.TempDir()
	gossh := filepath.Join(binDir, "gossh")
	gosshSCP := filepath.Join(binDir, "gossh-scp")
	for _, pair := range [][2]string{
		{gossh, "github.com/oscar/gossh/cmd/gossh"},
		{gosshSCP, "github.com/oscar/gossh/cmd/gossh-scp"},
	} {
		cmd := exec.Command("/usr/local/go/bin/go", "build", "-o", pair[0], pair[1])
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("build %s: %v", pair[1], err)
		}
	}

	hkPath := filepath.Join(home, "host_ed25519")
	hk, err := hostkey.LoadOrGenerate(hkPath, hostkey.Ed25519, 0, "h")
	if err != nil {
		t.Fatal(err)
	}
	idFile := filepath.Join(sshDir, "id_ed25519")
	if _, err := hostkey.LoadOrGenerate(idFile, hostkey.Ed25519, 0, "u"); err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(idFile + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	akPath := filepath.Join(home, "authorized_keys")
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
	port := l.Addr().(*net.TCPAddr).Port

	s, err := server.New(server.Config{
		HostKeys:       []ssh.Signer{hk.Signer},
		AuthorizedKeys: server.StaticAuthorizedKeys(entries),
		Shell:          "/bin/bash",
		AllowExec:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	srvCtx, cancel := context.WithCancel(context.Background())
	srvDone := make(chan struct{})
	go func() { defer close(srvDone); _ = s.Serve(srvCtx, l) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-srvDone:
		case <-time.After(2 * time.Second):
		}
	})
	time.Sleep(50 * time.Millisecond)

	knownHost := filepath.Join(sshDir, "known_hosts")
	if err := os.WriteFile(knownHost,
		[]byte(fmt.Sprintf("[127.0.0.1]:%d %s", port, ssh.MarshalAuthorizedKey(hk.Signer.PublicKey()))),
		0o600); err != nil {
		t.Fatal(err)
	}

	sshConfig := filepath.Join(sshDir, "config")
	cfg := fmt.Sprintf(`Host devbox
    Hostname 127.0.0.1
    Port %d
    User tester
    IdentityFile %s
    UserKnownHostsFile %s
    StrictHostKeyChecking yes
    ProxyCommand nc -q0 %%h %%p
`, port, idFile, knownHost)
	if err := os.WriteFile(sshConfig, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	return &e2eRig{
		port:      port,
		gossh:     gossh,
		gosshSCP:  gosshSCP,
		sshConfig: sshConfig,
		home:      home,
		knownHost: knownHost,
		idFile:    idFile,
	}
}

// runGossh invokes the built gossh binary with -F <ssh_config>; caller
// supplies any remaining args (typically `-T devbox <cmd>`).
func (r *e2eRig) runGossh(t *testing.T, timeout time.Duration, args ...string) (string, string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	full := append([]string{"-F", r.sshConfig}, args...)
	cmd := exec.CommandContext(ctx, r.gossh, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exit := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			exit = -1
		}
	}
	return stdout.String(), stderr.String(), exit
}

func (r *e2eRig) runSCP(t *testing.T, timeout time.Duration, args ...string) (string, string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	full := append([]string{"-F", r.sshConfig}, args...)
	cmd := exec.CommandContext(ctx, r.gosshSCP, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exit := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			exit = -1
		}
	}
	return stdout.String(), stderr.String(), exit
}

func TestE2EProxyCommandExec(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	r := setupE2E(t)
	stdout, stderr, exit := r.runGossh(t, 8*time.Second, "-T", "devbox", "echo proxy-path-ok")
	if exit != 0 {
		t.Fatalf("exit=%d stderr=%q", exit, stderr)
	}
	if !strings.Contains(stdout, "proxy-path-ok") {
		t.Fatalf("stdout=%q stderr=%q", stdout, stderr)
	}
}

// TestE2EProxyCommandShellInjectionBlocked is the regression guard for
// the host-in-%h injection vector: a malicious host arg must never
// reach `sh -c`. If this test starts passing "echo pwned" output, a
// validator was removed.
func TestE2EProxyCommandShellInjectionBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	r := setupE2E(t)
	// Drop the canonical devbox alias; feed a hostile target directly.
	sentinel := filepath.Join(t.TempDir(), "PWNED")
	hostileTarget := fmt.Sprintf("tester@127.0.0.1; touch %s; echo x", sentinel)
	_, stderr, exit := r.runGossh(t, 5*time.Second,
		"-p", fmt.Sprint(r.port),
		"-i", r.idFile,
		"-known-hosts", r.knownHost,
		"-proxy-command", "nc -q0 %h %p",
		"-T",
		hostileTarget, "echo should-not-run")
	if exit == 0 {
		t.Fatalf("injection NOT blocked; stderr=%q", stderr)
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatalf("!!! SECURITY REGRESSION: %s was created — shell injection succeeded", sentinel)
	}
	if !strings.Contains(stderr, "unsafe character") {
		t.Fatalf("expected 'unsafe character' error, got stderr=%q", stderr)
	}
}

// TestE2ESCPRecursiveRoundTrip uploads a non-trivial tree via SCP -r
// through ProxyCommand, then downloads it back, and asserts byte-
// identity of every regular file on the round trip. Regression guard
// for the "dstPath is an existing directory" semantics and for the
// recursive receiver's pathStack.
func TestE2ESCPRecursiveRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	r := setupE2E(t)

	// Build a source tree: top file, nested dir, deeper binary, dash
	// prefix (argv-injection canary), symlink (must be skipped).
	src := filepath.Join(t.TempDir(), "src_tree")
	mustMkdir(t, filepath.Join(src, "nested", "deeper"))
	payloads := map[string][]byte{
		"top.txt":                   []byte("hello from top\n"),
		"-dash.txt":                 []byte("dash-prefix ok\n"),
		"big.bin":                   bytesRand(t, 4096),
		"nested/inside.txt":         []byte("nested content\n"),
		"nested/deeper/deep.bin":    bytesRand(t, 2048),
	}
	for rel, data := range payloads {
		if err := os.WriteFile(filepath.Join(src, rel), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/etc/hostname", filepath.Join(src, "dangling")); err != nil {
		t.Fatal(err)
	}

	upDst := filepath.Join(t.TempDir(), "uploaded")
	if err := os.MkdirAll(upDst, 0o755); err != nil {
		t.Fatal(err)
	}
	_, stderr, exit := r.runSCP(t, 15*time.Second, "-r", src, "devbox:"+upDst+"/")
	if exit != 0 {
		t.Fatalf("upload exit=%d stderr=%q", exit, stderr)
	}

	// Round-trip: download back, compare to source.
	downDst := filepath.Join(t.TempDir(), "round_trip")
	if err := os.MkdirAll(downDst, 0o755); err != nil {
		t.Fatal(err)
	}
	_, stderr, exit = r.runSCP(t, 15*time.Second, "-r",
		"devbox:"+filepath.Join(upDst, "src_tree"), downDst+"/")
	if exit != 0 {
		t.Fatalf("download exit=%d stderr=%q", exit, stderr)
	}

	final := filepath.Join(downDst, "src_tree")
	for rel := range payloads {
		want, err := os.ReadFile(filepath.Join(src, rel))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(final, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: sha256(src)=%x sha256(rt)=%x",
				rel, sha256.Sum256(want), sha256.Sum256(got))
		}
	}
	// Symlinks are skipped by the uploader (not errors, not followed).
	if _, err := os.Lstat(filepath.Join(final, "dangling")); err == nil {
		t.Fatalf("symlink should not have been transferred")
	}
}

// TestE2ESCPSymlinkWriteRefused plants a symlink at the download target
// and expects the receiver to refuse to write through it. Without this
// guard, a malicious or compromised remote could redirect a write to
// anywhere the local user has access.
func TestE2ESCPSymlinkWriteRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	r := setupE2E(t)

	// Remote payload the attacker wants us to fetch.
	remote := filepath.Join(t.TempDir(), "remote_source.bin")
	if err := os.WriteFile(remote, []byte("content that would overwrite the symlink target"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Pre-plant a symlink at the download destination.
	dst := filepath.Join(t.TempDir(), "dst.bin")
	hijack := filepath.Join(t.TempDir(), "HIJACK_TARGET")
	if err := os.Symlink(hijack, dst); err != nil {
		t.Fatal(err)
	}

	_, stderr, exit := r.runSCP(t, 8*time.Second, "devbox:"+remote, dst)
	if exit == 0 {
		t.Fatalf("expected SCP to refuse; stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "refuse to write through existing symlink") {
		t.Fatalf("unexpected error: %q", stderr)
	}
	if _, err := os.Stat(hijack); err == nil {
		t.Fatalf("!!! SECURITY REGRESSION: hijack target was written")
	}
}

// TestE2ETmuxSessionPersistsAcrossConnections spins up a detached tmux
// server on the remote, then uses three SEPARATE gossh connections
// (each re-exec'ing nc via the ProxyCommand) to:
//   1. create the session,
//   2. send a command into its pane,
//   3. capture the pane and verify the output is there.
// This stresses the session.exec path, PTY-less tmux control, and
// that tmux's unix-socket state on the server is unaffected by our
// connection churn.
func TestE2ETmuxSessionPersistsAcrossConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	if _, err := exec.LookPath("tmux"); err != nil {
		t.Skip("tmux not installed")
	}
	r := setupE2E(t)

	// Use a per-test tmux socket so we don't collide with any other
	// tmux server owned by the user running the test.
	sock := "gossh-e2e-" + randSuffix(t)
	tmuxCmd := func(args string) string {
		return fmt.Sprintf("tmux -L %s %s", sock, args)
	}
	// Cleanup: always kill the tmux server we started, even on test failure.
	t.Cleanup(func() {
		_, _, _ = r.runGossh(t, 3*time.Second, "-T", "devbox",
			tmuxCmd("kill-server 2>/dev/null; echo cleaned"))
	})

	// Connection 1: create detached session.
	_, stderr, exit := r.runGossh(t, 6*time.Second, "-T", "devbox",
		tmuxCmd("new-session -d -s work 'bash --norc --noprofile -i'"))
	if exit != 0 {
		t.Fatalf("new-session: exit=%d stderr=%q", exit, stderr)
	}

	// Connection 2: send a marker command that we can spot in the pane.
	marker := "E2E-MARKER-" + randSuffix(t)
	_, stderr, exit = r.runGossh(t, 6*time.Second, "-T", "devbox",
		tmuxCmd(fmt.Sprintf("send-keys -t work 'echo %s' Enter", marker)))
	if exit != 0 {
		t.Fatalf("send-keys: exit=%d stderr=%q", exit, stderr)
	}

	// Poll capture-pane from a THIRD connection until we see the
	// marker. Polling avoids flakes under CI load: bash inside the
	// tmux pane processes send-keys asynchronously.
	deadline := time.Now().Add(6 * time.Second)
	for {
		stdout, stderr, exit := r.runGossh(t, 4*time.Second, "-T", "devbox",
			tmuxCmd("capture-pane -t work -p"))
		if exit == 0 && strings.Contains(stdout, marker) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("marker %q never appeared in tmux pane\nstdout=%q\nstderr=%q",
				marker, stdout, stderr)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func bytesRand(t *testing.T, n int) []byte {
	t.Helper()
	f, err := os.Open("/dev/urandom")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := make([]byte, n)
	if _, err := f.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func randSuffix(t *testing.T) string {
	t.Helper()
	b := bytesRand(t, 6)
	return fmt.Sprintf("%x", b)
}

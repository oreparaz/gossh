package main_test

// Real-PTY regression tests for the interactive-shell path.
//
// Everything else in e2e_session_test.go runs gossh in non-PTY mode
// (`-T`). That covers the SSH channel itself but misses four client
// code paths that can regress silently:
//
//   - term.MakeRaw on the local slave
//   - RequestPty size propagation
//   - SIGWINCH → s.WindowChange on resize
//   - bidirectional byte passthrough under line discipline
//
// These tests spawn the built gossh attached to a creack/pty master,
// drive it as if a human were at the keyboard, and assert on what
// comes back. They skip under -short and when bash isn't available.

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

// TestE2EPTYInteractiveShellAndResize is the one test that exercises
// the whole interactive stack at once:
//  1. Open a local PTY at 24x80 and TERM=e2e-xterm.
//  2. Exec `gossh devbox` (no command → Shell mode, which sets up
//     termios + SIGWINCH forwarding).
//  3. Read the first prompt, inject `stty size`, expect "24 80".
//  4. Inject a uniquely-marked echo to prove bytes round-trip.
//  5. Resize master to 40x120, inject `stty size` again, expect
//     "40 120" within a bounded deadline — proving window-change
//     reached the remote and updated its pty termios.
//  6. Send `exit` to unwind cleanly.
//
// One test body, four independent regressions caught.
func TestE2EPTYInteractiveShellAndResize(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	r := setupE2E(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, r.gossh, "-F", r.sshConfig, "devbox")
	// TERM lives in the child's env; the remote gets it via env
	// request (x/crypto/ssh's RequestPty carries the terminal name,
	// but env vars still flow through ssh.Session.Setenv — here we
	// rely on the default TERM plumbed by Shell()).
	cmd.Env = append(os.Environ(), "TERM=e2e-xterm")

	// Start small on purpose (24×80) so the resize step has somewhere
	// to go. Wrapping isn't a concern here because `stty size` output
	// is short.
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		t.Fatalf("pty.StartWithSize: %v", err)
	}
	t.Cleanup(func() {
		_ = ptmx.Close()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	reader := bufio.NewReader(ptmx)

	// The remote shell is bash in interactive mode. It will print a
	// prompt; wait for anything that looks shell-ish before typing.
	waitFor(t, reader, regexp.MustCompile(`[\$#]\s*$|\$ $`), 5*time.Second, "initial prompt")

	// Initial size: inject `stty size` via a marker we can grep for.
	send(t, ptmx, "stty size; echo SZ1-DONE\n")
	out := waitFor(t, reader, regexp.MustCompile(`(?m)^(\d+)\s+(\d+)\s*\r?\nSZ1-DONE`), 5*time.Second, "initial stty size")
	if rows, cols := extractSize(t, out); rows != 24 || cols != 80 {
		t.Fatalf("initial size wrong: rows=%d cols=%d (want 24 80)\nbuffer=%q", rows, cols, out)
	}

	// Byte passthrough: round-trip a unique string both directions.
	send(t, ptmx, "echo PASSTHROUGH-CANARY-ABCXYZ\n")
	waitFor(t, reader, regexp.MustCompile(`PASSTHROUGH-CANARY-ABCXYZ\r?\n`), 5*time.Second, "echo round-trip")

	// Resize → SIGWINCH → window-change forwarded → remote pty
	// termios updated. Poll `stty size` because the remote's view of
	// the new size updates asynchronously.
	if err := pty.Setsize(ptmx, &pty.Winsize{Rows: 40, Cols: 120}); err != nil {
		t.Fatalf("pty.Setsize: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	seenResize := false
	for time.Now().Before(deadline) {
		send(t, ptmx, "stty size; echo SZ2-DONE\n")
		out := waitFor(t, reader, regexp.MustCompile(`(?m)^(\d+)\s+(\d+)\s*\r?\nSZ2-DONE`), 2*time.Second, "post-resize stty size")
		if rows, cols := extractSize(t, out); rows == 40 && cols == 120 {
			seenResize = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !seenResize {
		t.Fatalf("SIGWINCH did not propagate: remote pty never saw 40x120")
	}

	// Clean exit: close stdin-equivalent by sending `exit` + close
	// pty. gossh's Shell() returns when the remote shell exits.
	send(t, ptmx, "exit\n")
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	select {
	case <-waitCh:
		// ok — any exit status is fine here
	case <-time.After(5 * time.Second):
		t.Fatalf("gossh did not exit after remote shell exited")
	}
}

// TestE2EPTYRejectsNonTerminal is the regression guard for the check
// at shell.go:25/108. Without a PTY, `gossh host` (Shell mode) and
// `gossh -t host cmd` (ExecInteractive) must both refuse rather than
// silently degrade. Removing those checks would let a pipe-fed gossh
// enter raw mode against a non-TTY fd, which corrupts the terminal
// of whatever shell ran gossh.
func TestE2EPTYRejectsNonTerminal(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	r := setupE2E(t)

	// Shell mode (no command) with stdin=/dev/null.
	_, stderr, exit := r.runGossh(t, 4*time.Second, "devbox")
	if exit == 0 || !strings.Contains(stderr, "stdin is not a terminal") {
		t.Fatalf("Shell-mode refusal missing; exit=%d stderr=%q", exit, stderr)
	}

	// -t <cmd> mode.
	_, stderr, exit = r.runGossh(t, 4*time.Second, "-t", "devbox", "echo x")
	if exit == 0 || !strings.Contains(stderr, "stdin is not a terminal") {
		t.Fatalf("-t refusal missing; exit=%d stderr=%q", exit, stderr)
	}
}

// TestE2EPTYForwardsSIGINTCleanly: in PTY mode, a Ctrl-C typed on the
// local tty becomes a 0x03 byte in raw mode, which SSH carries to the
// remote where the pty line discipline turns it into SIGINT on the
// foreground process group. This test verifies the CHARACTER makes
// it through (the rest is the kernel's job). Regression signal: if
// gossh ever stops forwarding stdin bytes under raw mode, long-
// running commands become uninterruptible.
func TestE2EPTYForwardsSIGINTCleanly(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	r := setupE2E(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.gossh, "-F", r.sshConfig, "devbox")
	cmd.Env = append(os.Environ(), "TERM=e2e-xterm")
	// 200 cols: keep bash from column-wrapping echoed input, which
	// would fragment our canary with CRs mid-word.
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 200})
	if err != nil {
		t.Fatalf("pty.Start: %v", err)
	}
	t.Cleanup(func() {
		_ = ptmx.Close()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	reader := bufio.NewReader(ptmx)
	waitFor(t, reader, regexp.MustCompile(`[\$#]\s*$|\$ $`), 5*time.Second, "prompt")

	// Start an intentionally long-running command.
	send(t, ptmx, "sleep 300\n")
	// Give bash a beat to actually launch the sleep.
	time.Sleep(400 * time.Millisecond)

	start := time.Now()
	if _, err := ptmx.Write([]byte{0x03}); err != nil {
		t.Fatalf("write ^C: %v", err)
	}

	// If SIGINT propagated, bash kills sleep and we're back at a
	// prompt immediately. Fire a canary echo and expect it to come
	// back fast. If SIGINT didn't propagate, sleep holds the
	// foreground and our echo line sits unread for 300 seconds.
	send(t, ptmx, "echo CTRL_C_OK_$$\n")
	waitFor(t, reader, regexp.MustCompile(`CTRL_C_OK_\d+`), 4*time.Second, "post-SIGINT canary")
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("SIGINT + canary took %v — remote may not have received SIGINT promptly", elapsed)
	}

	send(t, ptmx, "exit\n")
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	select {
	case <-waitCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("gossh did not exit")
	}
}

// ---- helpers ----------------------------------------------------

func send(t *testing.T, w io.Writer, s string) {
	t.Helper()
	if _, err := w.Write([]byte(s)); err != nil {
		// EIO is what happens when the pty slave is gone; treat it
		// as a test-scope error rather than a hang.
		if err == syscall.EIO {
			t.Fatalf("pty write got EIO — child likely exited: %q", s)
		}
		t.Fatalf("pty write %q: %v", s, err)
	}
}

// waitFor reads from r until the buffered output matches pat or the
// deadline expires. Returns the full accumulated buffer (so callers
// can extract capture groups from pat directly, or inspect context
// on failure).
func waitFor(t *testing.T, r *bufio.Reader, pat *regexp.Regexp, d time.Duration, label string) string {
	t.Helper()
	deadline := time.Now().Add(d)
	var buf strings.Builder
	chunk := make([]byte, 1024)
	for time.Now().Before(deadline) {
		// Poll the pty with a small read deadline via a goroutine +
		// channel — os/exec pty has no SetReadDeadline.
		type readResult struct {
			n   int
			err error
		}
		ch := make(chan readResult, 1)
		go func() {
			n, err := r.Read(chunk)
			ch <- readResult{n, err}
		}()
		select {
		case rr := <-ch:
			if rr.n > 0 {
				buf.Write(chunk[:rr.n])
				if pat.MatchString(buf.String()) {
					return buf.String()
				}
			}
			if rr.err != nil {
				t.Fatalf("waitFor(%s): read error %v\nbuffer=%q", label, rr.err, buf.String())
			}
		case <-time.After(200 * time.Millisecond):
			// Check deadline at top of loop.
		}
	}
	t.Fatalf("waitFor(%s) timed out after %v\npattern=%s\nbuffer=%q",
		label, d, pat, buf.String())
	return ""
}

var sizeRe = regexp.MustCompile(`(?m)^(\d+)\s+(\d+)\s*$`)

// extractSize pulls the "rows cols" line out of a buffer containing
// a `stty size` response. It picks the LAST such line, since earlier
// matches may be the echoed input line under certain termios modes.
func extractSize(t *testing.T, out string) (rows, cols int) {
	t.Helper()
	matches := sizeRe.FindAllStringSubmatch(out, -1)
	if len(matches) == 0 {
		t.Fatalf("no 'rows cols' line in buffer: %q", out)
	}
	last := matches[len(matches)-1]
	_, _ = fmt.Sscanf(last[1], "%d", &rows)
	_, _ = fmt.Sscanf(last[2], "%d", &cols)
	return rows, cols
}

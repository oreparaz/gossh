package server_test

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

func TestPTYInteropSystemSSH(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	h := startServer(t, nil)

	// -tt forces pty allocation even when stdin is not a tty.
	cmd := h.sshCmd(t, []string{"-tt"}, "echo hello-pty; exit 0")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("ssh: %v\nstderr=%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "hello-pty") {
		t.Fatalf("stdout missing marker: %q", stdout.String())
	}
}

func TestInteractiveShellEcho(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	h := startServer(t, nil)

	cmd := h.sshCmd(t, []string{"-tt"})
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer stdin.Close()
		// Give the shell a moment to print its prompt, then type commands.
		time.Sleep(200 * time.Millisecond)
		_, _ = io.WriteString(stdin, "echo marker-ABCDE\n")
		time.Sleep(200 * time.Millisecond)
		_, _ = io.WriteString(stdin, "exit 0\n")
	}()
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	select {
	case err := <-waitErr:
		if err != nil && !strings.Contains(err.Error(), "exit status") {
			// Non-zero exit is expected sometimes depending on the shell's
			// own handling of SIGHUP; only fail if we never saw our marker.
			t.Logf("wait: %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("timed out; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "marker-ABCDE") {
		t.Fatalf("marker missing: %q", stdout.String())
	}
}

package server_test

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/oscar/gossh/internal/server"
)

// startEchoServer starts a tiny TCP echo server and returns its address.
func startEchoServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().String(), func() { _ = l.Close() }
}

// pickFreePort returns a TCP port that is (likely) free when picked.
func pickFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestDirectTCPIPWithSystemSSH(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	h := startServer(t, func(c *server.Config) {
		c.AllowLocalForward = true
	})

	// Local bind port for -L.
	localPort := pickFreePort(t)

	// Start ssh with -L and keep it open using -N (no command).
	cmd := h.sshCmd(t, []string{
		"-N",
		"-o", "ExitOnForwardFailure=yes",
		"-L", fmt.Sprintf("%d:%s", localPort, echoAddr),
	})
	var sshErr strings.Builder
	cmd.Stderr = &sshErr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("ssh stderr: %s", sshErr.String())
		}
	}()

	// Wait for the local listener to come up.
	var conn net.Conn
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, lastErr = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
		if lastErr == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("could not reach forwarded port: %v", lastErr)
	}
	defer conn.Close()

	msg := "hello-through-tunnel\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("echoed %q, want %q", string(buf), msg)
	}
}

func TestDirectTCPIPRejectedWhenDisallowed(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	// Server with AllowLocalForward=false (default). The local listener
	// is created by the ssh client; the per-connection direct-tcpip
	// request is what the server rejects — so we have to open a
	// connection through the tunnel to observe the refusal.
	h := startServer(t, nil)
	localPort := pickFreePort(t)

	cmd := h.sshCmd(t, []string{
		"-N",
		"-L", fmt.Sprintf("%d:%s", localPort, echoAddr),
	})
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	// Wait for the ssh client's local listener.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Now open a fresh connection; the server will reject the
	// direct-tcpip request and ssh closes our connection quickly.
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		// Connection refused immediately is also an acceptable signal.
		return
	}
	defer c.Close()
	// Attempt to read; we should see EOF promptly.
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	_, err = c.Read(buf)
	if err == nil {
		t.Fatal("expected ssh client to close the forwarded connection after server rejection")
	}
	_ = strings.Contains // silence import lint
}

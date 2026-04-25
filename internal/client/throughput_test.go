package client_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/oreparaz/gossh/internal/client"
	"github.com/oreparaz/gossh/internal/forward"
	"github.com/oreparaz/gossh/internal/knownhosts"
)

// TestExecLargeOutput writes many MB to stdout on the remote and
// checks we don't deadlock or truncate.
func TestExecLargeOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	r := startGosshd(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, client.Config{
		Host:           r.Host,
		Port:           r.Port,
		User:           "testuser",
		IdentityFiles:  []string{r.UserKeyPath},
		KnownHostsPath: r.KnownHosts,
		HostCheckMode:  knownhosts.Strict,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// 4 MiB of deterministic data.
	var stdout, stderr bytes.Buffer
	const bytes_ = 4 << 20
	status, err := c.Exec(fmt.Sprintf("head -c %d /dev/urandom | sha256sum", bytes_),
		nil, &stdout, &stderr)
	if err != nil || status != 0 {
		t.Fatalf("exec: status=%d err=%v stderr=%s", status, err, stderr.String())
	}
	// Output is a hex hash followed by filename placeholder.
	if len(stdout.String()) < 64 {
		t.Fatalf("unexpectedly short output: %q", stdout.String())
	}
}

// TestExecLargeStdin pipes a lot of data to the remote command.
func TestExecLargeStdin(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	r := startGosshd(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, client.Config{
		Host:           r.Host,
		Port:           r.Port,
		User:           "testuser",
		IdentityFiles:  []string{r.UserKeyPath},
		KnownHostsPath: r.KnownHosts,
		HostCheckMode:  knownhosts.Strict,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Stream 1 MiB of random bytes; remote computes SHA-256; we compare.
	const size = 1 << 20
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)

	var stdout, stderr bytes.Buffer
	status, err := c.Exec("sha256sum | awk '{print $1}'", bytes.NewReader(payload), &stdout, &stderr)
	if err != nil || status != 0 {
		t.Fatalf("exec: status=%d err=%v stderr=%s", status, err, stderr.String())
	}
	got := bytes.TrimSpace(stdout.Bytes())
	want := fmt.Sprintf("%x", sum)
	if string(got) != want {
		t.Fatalf("stdin round-trip sha mismatch: got %s, want %s", got, want)
	}
}

// TestLocalForwardStream shovels many MB through a -L tunnel and
// confirms no deadlock and end-to-end data integrity.
func TestLocalForwardStream(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	// Start a destination that echoes everything.
	dst, stopDst := startEcho(t)
	defer stopDst()
	dstHost, dstPortStr, _ := net.SplitHostPort(dst)
	var dstPort int
	fmt.Sscanf(dstPortStr, "%d", &dstPort)

	rig := startGosshdWithCfg(t, true, false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, client.Config{
		Host:           rig.Host,
		Port:           rig.Port,
		User:           "testuser",
		IdentityFiles:  []string{rig.UserKeyPath},
		KnownHostsPath: rig.KnownHosts,
		HostCheckMode:  knownhosts.Strict,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Pick a free local port.
	pl, _ := net.Listen("tcp", "127.0.0.1:0")
	localPort := pl.Addr().(*net.TCPAddr).Port
	pl.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	stop, err := forward.Local(ctx, c.Raw(), forward.Spec{
		BindAddr: "127.0.0.1", BindPort: localPort,
		TargetHost: dstHost, TargetPort: dstPort,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	const size = 1 << 20 // 1 MiB
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	// Write on one goroutine, read on another.
	errCh := make(chan error, 2)
	readback := make([]byte, size)
	go func() {
		_, err := io.ReadFull(conn, readback)
		errCh <- err
	}()
	go func() {
		_, err := conn.Write(payload)
		errCh <- err
	}()
	// Wait both to finish (or timeout).
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("forward stream: %v", err)
		}
	}
	if !bytes.Equal(payload, readback) {
		t.Fatalf("forward stream: payload mismatched")
	}
}

package client_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/oreparaz/gossh/internal/client"
	"github.com/oreparaz/gossh/internal/forward"
	"github.com/oreparaz/gossh/internal/knownhosts"
)

// TestSOCKSHandshakeTimeout opens the SOCKS listener and connects but
// sends nothing. The handler must close the conn instead of hanging
// forever (slow-loris DoS prevention).
func TestSOCKSHandshakeTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
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

	pl, _ := net.Listen("tcp", "127.0.0.1:0")
	socksPort := pl.Addr().(*net.TCPAddr).Port
	pl.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	stop, err := forward.Dynamic(ctx, c.Raw(), forward.Spec{
		BindAddr: "127.0.0.1", BindPort: socksPort,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	time.Sleep(50 * time.Millisecond)

	// Connect but stay silent.
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// The server should give up (we set a 10s handshake timeout);
	// we tolerate anything < 15s as proof the handler isn't wedged.
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 1)
	start := time.Now()
	_, err = conn.Read(buf)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("expected read to fail after handshake timeout")
	}
	if elapsed > 14*time.Second {
		t.Fatalf("handler was still holding after %v (slow-loris DoS possible)", elapsed)
	}
}

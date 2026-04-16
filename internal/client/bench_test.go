package client_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/oscar/gossh/internal/client"
	"github.com/oscar/gossh/internal/forward"
	"github.com/oscar/gossh/internal/knownhosts"
)

// BenchmarkExecSmall measures exec overhead for a trivial command.
// Useful as a regression check on handshake latency and session open.
func BenchmarkExecSmall(b *testing.B) {
	r := startGosshdB(b)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := client.Dial(ctx, client.Config{
		Host: r.Host, Port: r.Port, User: "u",
		IdentityFiles:  []string{r.UserKeyPath},
		KnownHostsPath: r.KnownHosts,
		HostCheckMode:  knownhosts.Strict,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		if _, err := c.Exec("echo x", nil, &out, io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkForwardThroughput benchmarks data rate over a -L tunnel.
// Reports bytes/op so b.SetBytes is honoured by -benchmem.
func BenchmarkForwardThroughput(b *testing.B) {
	dst, stopDst := startEchoB(b)
	defer stopDst()
	dstHost, dstPortStr, _ := net.SplitHostPort(dst)
	var dstPort int
	for _, c := range dstPortStr {
		dstPort = dstPort*10 + int(c-'0')
	}

	r := startGosshdBWithForward(b)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c, err := client.Dial(ctx, client.Config{
		Host: r.Host, Port: r.Port, User: "u",
		IdentityFiles:  []string{r.UserKeyPath},
		KnownHostsPath: r.KnownHosts,
		HostCheckMode:  knownhosts.Strict,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()

	pl, _ := net.Listen("tcp", "127.0.0.1:0")
	localPort := pl.Addr().(*net.TCPAddr).Port
	pl.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	stop, err := forward.Local(ctx, c.Raw(), forward.Spec{
		BindAddr: "127.0.0.1", BindPort: localPort,
		TargetHost: dstHost, TargetPort: dstPort,
	}, log)
	if err != nil {
		b.Fatal(err)
	}
	defer stop()

	time.Sleep(50 * time.Millisecond)

	const chunk = 64 << 10 // 64 KiB
	buf := make([]byte, chunk)
	rand.Read(buf)
	rx := make([]byte, chunk)

	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(localPort)))
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))

	b.ResetTimer()
	b.SetBytes(int64(chunk))
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(buf); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(conn, rx); err != nil {
			b.Fatal(err)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 6)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

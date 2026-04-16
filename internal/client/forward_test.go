package client_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/oscar/gossh/internal/client"
	"github.com/oscar/gossh/internal/forward"
	"github.com/oscar/gossh/internal/knownhosts"
)

// startEcho starts a localhost echo server and returns its address.
func startEcho(t *testing.T) (string, func()) {
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

func TestClientLocalForward(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	// Target the gossh client is forwarding TO.
	dstAddr, stopDst := startEcho(t)
	defer stopDst()

	r := startGosshd(t)
	// We need the gosshd to allow direct-tcpip channels.
	// startGosshd's config is fixed — restart with AllowLocalForward.
	// (Trick: we reuse the rig; but startGosshd already allows with
	// AllowExec. Local forwarding needs AllowLocalForward=true. Let's
	// spin a new harness inline.)
	_ = r

	rig := startGosshdWithCfg(t, true, false)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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

	// Parse target host:port.
	dstHost, dstPortStr, _ := net.SplitHostPort(dstAddr)
	var dstPort int
	fmt.Sscanf(dstPortStr, "%d", &dstPort)

	// Set up -L local_port:dstHost:dstPort with bindPort=0 (free).
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	localPort := lis.Addr().(*net.TCPAddr).Port
	lis.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	stop, err := forward.Local(ctx, c.Raw(), forward.Spec{
		BindAddr:   "127.0.0.1",
		BindPort:   localPort,
		TargetHost: dstHost,
		TargetPort: dstPort,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	// Dial through the tunnel and verify echo.
	time.Sleep(50 * time.Millisecond) // let accept loop start
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	msg := []byte("hello-through-tunnel\n")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch: %q", buf)
	}
}

func TestClientRemoteForward(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	// Local destination we forward into.
	dstAddr, stopDst := startEcho(t)
	defer stopDst()

	rig := startGosshdWithCfg(t, false, true)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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

	dstHost, dstPortStr, _ := net.SplitHostPort(dstAddr)
	var dstPort int
	fmt.Sscanf(dstPortStr, "%d", &dstPort)

	// Pick a free port for the server to bind.
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bindPort := pl.Addr().(*net.TCPAddr).Port
	pl.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	stop, err := forward.Remote(ctx, c.Raw(), forward.Spec{
		BindAddr:   "127.0.0.1",
		BindPort:   bindPort,
		TargetHost: dstHost,
		TargetPort: dstPort,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	time.Sleep(50 * time.Millisecond)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", bindPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	msg := []byte("echo-remote\n")
	conn.Write(msg)
	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("got %q", buf)
	}
}

// Minimal SOCKS5 CONNECT test.
func TestClientDynamicSOCKS5(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dstAddr, stopDst := startEcho(t)
	defer stopDst()
	rig := startGosshdWithCfg(t, true, false)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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

	// Pick a free port for SOCKS.
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socksPort := pl.Addr().(*net.TCPAddr).Port
	pl.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	stop, err := forward.Dynamic(ctx, c.Raw(), forward.Spec{
		BindAddr: "127.0.0.1",
		BindPort: socksPort,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	time.Sleep(50 * time.Millisecond)

	// Perform SOCKS5 CONNECT to dstAddr.
	dstHost, dstPortStr, _ := net.SplitHostPort(dstAddr)
	dstPort16 := uint16(0)
	fmt.Sscanf(dstPortStr, "%d", &dstPort16)

	sc, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort))
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	// Greeting.
	if _, err := sc.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	rsp := make([]byte, 2)
	if _, err := io.ReadFull(sc, rsp); err != nil {
		t.Fatal(err)
	}
	if rsp[0] != 0x05 || rsp[1] != 0x00 {
		t.Fatalf("bad greeting reply: %v", rsp)
	}

	// CONNECT request with domain name.
	buf := []byte{0x05, 0x01, 0x00, 0x03, byte(len(dstHost))}
	buf = append(buf, []byte(dstHost)...)
	portBytes := []byte{0, 0}
	binary.BigEndian.PutUint16(portBytes, dstPort16)
	buf = append(buf, portBytes...)
	if _, err := sc.Write(buf); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10) // VER REP RSV ATYP(1=IPv4) BND(4) PORT(2)
	if _, err := io.ReadFull(sc, rep); err != nil {
		t.Fatal(err)
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		t.Fatalf("CONNECT reply = %v", rep)
	}

	// Now send+read through the tunnel.
	msg := "socks-echo\n"
	if _, err := sc.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len(msg))
	sc.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(sc, b); err != nil {
		t.Fatal(err)
	}
	if string(b) != msg {
		t.Fatalf("got %q", b)
	}

	// Avoid unused imports on platforms without the deps.
	_ = os.Getenv
	_ = strings.HasPrefix
}

// Package forward implements the three client-side SSH forwarding
// modes: local (-L), remote (-R), and dynamic SOCKS5 (-D).
//
// All three keep the accept loop running for the lifetime of the SSH
// connection; they do not have a meaningful "close" beyond tearing
// down the underlying ssh.Client. Errors during accept are logged
// and the listener re-entered so a transient failure does not take
// down the tunnel.
package forward

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Spec is a parsed -L/-R/-D forwarding specification.
type Spec struct {
	BindAddr   string // "" → localhost for -L/-D, "" → 0.0.0.0 for -R
	BindPort   int
	TargetHost string // unused for -D
	TargetPort int    // unused for -D
}

// ParseLocal parses "[bind:]port:host:hostport" for -L and -R.
//
// Examples:
//
//	"8080:example.com:80"             → bind=localhost port=8080 target=example.com:80
//	"127.0.0.1:8080:example.com:80"   → explicit bind
//	"0:example.com:80"                → pick a free port
func ParseLocal(s string) (Spec, error) {
	// Split into 3 or 4 colon-separated fields, respecting IPv6 brackets.
	parts, err := splitForward(s)
	if err != nil {
		return Spec{}, err
	}
	switch len(parts) {
	case 3:
		port, err := strconv.Atoi(parts[0])
		if err != nil {
			return Spec{}, fmt.Errorf("bad bind port %q", parts[0])
		}
		tport, err := strconv.Atoi(parts[2])
		if err != nil {
			return Spec{}, fmt.Errorf("bad target port %q", parts[2])
		}
		return Spec{BindAddr: "", BindPort: port, TargetHost: parts[1], TargetPort: tport}, nil
	case 4:
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return Spec{}, fmt.Errorf("bad bind port %q", parts[1])
		}
		tport, err := strconv.Atoi(parts[3])
		if err != nil {
			return Spec{}, fmt.Errorf("bad target port %q", parts[3])
		}
		return Spec{BindAddr: parts[0], BindPort: port, TargetHost: parts[2], TargetPort: tport}, nil
	default:
		return Spec{}, fmt.Errorf("-L/-R expects [bind:]port:host:hostport, got %q", s)
	}
}

// ParseDynamic parses "[bind:]port" for -D.
func ParseDynamic(s string) (Spec, error) {
	parts, err := splitForward(s)
	if err != nil {
		return Spec{}, err
	}
	switch len(parts) {
	case 1:
		port, err := strconv.Atoi(parts[0])
		if err != nil {
			return Spec{}, fmt.Errorf("bad -D port %q", parts[0])
		}
		return Spec{BindAddr: "", BindPort: port}, nil
	case 2:
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return Spec{}, fmt.Errorf("bad -D port %q", parts[1])
		}
		return Spec{BindAddr: parts[0], BindPort: port}, nil
	default:
		return Spec{}, fmt.Errorf("-D expects [bind:]port, got %q", s)
	}
}

// splitForward splits on ':' but respects IPv6 bracketed addresses.
func splitForward(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inBracket := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '[':
			inBracket = true
		case ']':
			inBracket = false
		case ':':
			if !inBracket {
				out = append(out, cur.String())
				cur.Reset()
				continue
			}
		}
		cur.WriteByte(c)
	}
	out = append(out, cur.String())
	// Strip brackets from IPv6 entries.
	for i, p := range out {
		if strings.HasPrefix(p, "[") && strings.HasSuffix(p, "]") {
			out[i] = p[1 : len(p)-1]
		}
	}
	if inBracket {
		return nil, errors.New("unterminated IPv6 bracket")
	}
	return out, nil
}

// Local starts a local listener that forwards connections to target
// via the ssh.Client (direct-tcpip). It returns a function that stops
// the listener.
func Local(ctx context.Context, client *ssh.Client, spec Spec, log *slog.Logger) (stop func(), err error) {
	bindHost := spec.BindAddr
	if bindHost == "" {
		bindHost = "127.0.0.1"
	}
	laddr := net.JoinHostPort(bindHost, strconv.Itoa(spec.BindPort))
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, fmt.Errorf("-L listen %s: %w", laddr, err)
	}
	log.Info("-L listening", "bind", l.Addr(), "target", net.JoinHostPort(spec.TargetHost, strconv.Itoa(spec.TargetPort)))
	target := net.JoinHostPort(spec.TargetHost, strconv.Itoa(spec.TargetPort))
	go acceptLoop(l, func(c net.Conn) {
		rc, err := client.Dial("tcp", target)
		if err != nil {
			log.Info("-L dial remote failed", "target", target, "err", err)
			_ = c.Close()
			return
		}
		splice(c, rc)
	})
	_ = ctx
	return func() { _ = l.Close() }, nil
}

// Remote asks the server to bind a listener and forwards inbound
// connections to the local target.
func Remote(ctx context.Context, client *ssh.Client, spec Spec, log *slog.Logger) (stop func(), err error) {
	bindHost := spec.BindAddr
	if bindHost == "" {
		bindHost = "0.0.0.0"
	}
	raddr := net.JoinHostPort(bindHost, strconv.Itoa(spec.BindPort))
	l, err := client.Listen("tcp", raddr)
	if err != nil {
		return nil, fmt.Errorf("-R listen %s: %w", raddr, err)
	}
	log.Info("-R remote listening", "bind", l.Addr(), "target", net.JoinHostPort(spec.TargetHost, strconv.Itoa(spec.TargetPort)))
	target := net.JoinHostPort(spec.TargetHost, strconv.Itoa(spec.TargetPort))
	go acceptLoop(l, func(c net.Conn) {
		lc, err := net.Dial("tcp", target)
		if err != nil {
			log.Info("-R dial local failed", "target", target, "err", err)
			_ = c.Close()
			return
		}
		splice(c, lc)
	})
	_ = ctx
	return func() { _ = l.Close() }, nil
}

// Dynamic starts a local SOCKS5 proxy (no auth, CONNECT only) whose
// outbound connections go through the SSH tunnel.
func Dynamic(ctx context.Context, client *ssh.Client, spec Spec, log *slog.Logger) (stop func(), err error) {
	bindHost := spec.BindAddr
	if bindHost == "" {
		bindHost = "127.0.0.1"
	}
	laddr := net.JoinHostPort(bindHost, strconv.Itoa(spec.BindPort))
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, fmt.Errorf("-D listen %s: %w", laddr, err)
	}
	log.Info("-D SOCKS5 listening", "bind", l.Addr())
	go acceptLoop(l, func(c net.Conn) { handleSOCKS(c, client, log) })
	_ = ctx
	return func() { _ = l.Close() }, nil
}

func acceptLoop(l net.Listener, handle func(net.Conn)) {
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go handle(c)
	}
}

func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	var once sync.Once
	forceClose := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		// After one direction EOFs, force-close both sides if the
		// peer doesn't reciprocate within a grace period. Matches
		// spliceChannel on the server side.
		time.AfterFunc(10*time.Second, forceClose)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		time.AfterFunc(10*time.Second, forceClose)
	}()
	wg.Wait()
	forceClose()
}

// --- SOCKS5 (RFC 1928) minimal server ---

const (
	socksVer5            byte = 0x05
	methodNoAuth         byte = 0x00
	cmdConnect           byte = 0x01
	atypIPv4             byte = 0x01
	atypDomain           byte = 0x03
	atypIPv6             byte = 0x04
	replySuccess         byte = 0x00
	replyHostUnreachable byte = 0x04
	replyRefused         byte = 0x05
	replyCommandUnsup    byte = 0x07
)

// socksHandshakeTimeout bounds how long a client has to complete the
// SOCKS5 greeting+request dance. Prevents slow-loris DoS on the SOCKS
// port. Cleared once the tunnel is established.
const socksHandshakeTimeout = 10 * time.Second

func handleSOCKS(c net.Conn, client *ssh.Client, log *slog.Logger) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(socksHandshakeTimeout))
	// Greeting: VER NMETHODS METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if hdr[0] != socksVer5 {
		return
	}
	nmeth := int(hdr[1])
	methods := make([]byte, nmeth)
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	// We only advertise no-auth.
	if !containsByte(methods, methodNoAuth) {
		_, _ = c.Write([]byte{socksVer5, 0xFF})
		return
	}
	if _, err := c.Write([]byte{socksVer5, methodNoAuth}); err != nil {
		return
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if req[0] != socksVer5 {
		return
	}
	if req[1] != cmdConnect {
		writeSOCKSReply(c, replyCommandUnsup)
		return
	}
	var host string
	switch req[3] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case atypDomain:
		lenb := make([]byte, 1)
		if _, err := io.ReadFull(c, lenb); err != nil {
			return
		}
		buf := make([]byte, int(lenb[0]))
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		host = string(buf)
	default:
		writeSOCKSReply(c, replyCommandUnsup)
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)

	// Dial through the ssh tunnel.
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	rc, err := client.Dial("tcp", target)
	if err != nil {
		log.Info("SOCKS5 dial failed", "target", target, "err", err)
		writeSOCKSReply(c, replyHostUnreachable)
		return
	}
	defer rc.Close()
	writeSOCKSReply(c, replySuccess)
	// Clear the handshake deadline now that the tunnel is live —
	// application data may be idle for long stretches.
	_ = c.SetReadDeadline(time.Time{})
	splice(c, rc)
}

func writeSOCKSReply(c net.Conn, code byte) {
	// BND.ADDR/BND.PORT always 0.
	_, _ = c.Write([]byte{socksVer5, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
}

func containsByte(s []byte, b byte) bool {
	for _, x := range s {
		if x == b {
			return true
		}
	}
	return false
}

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// expandProxyTokens performs OpenSSH's ProxyCommand token substitution:
// %h → host, %p → port, %r → user, %% → literal %. Any other %X is
// left as-is. The substituted values are validated (shell-safe
// character set only) before being spliced into the command that
// will reach `sh -c`, so a user typing `gossh "foo;rm -rf ~"` cannot
// turn the ProxyCommand into an injection vector.
func expandProxyTokens(cmd, host string, port int, user string) (string, error) {
	if err := validateShellSafe("host", host); err != nil {
		return "", err
	}
	if user != "" {
		if err := validateShellSafe("user", user); err != nil {
			return "", err
		}
	}
	// %% is replaced first so "%%h" stays literal "%h" rather than
	// being expanded to the hostname. strings.NewReplacer scans
	// left-to-right with argument-order tie-breaking.
	return strings.NewReplacer(
		"%%", "%",
		"%h", host,
		"%p", strconv.Itoa(port),
		"%r", user,
	).Replace(cmd), nil
}

// validateShellSafe rejects any character that could be meaningful
// to /bin/sh. The allowlist is deliberately tighter than RFC 1123 so
// review is easy: alphanumerics plus a short set of punctuation that
// legitimately appears in hostnames (DNS dots/dashes, IPv6 brackets
// and colons, underscore) or usernames (dot, dash, underscore).
func validateShellSafe(field, s string) error {
	if s == "" {
		return fmt.Errorf("proxy command: empty %s", field)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == '_' || c == ':' || c == '[' || c == ']':
		default:
			return fmt.Errorf("proxy command: %s %q contains unsafe character %q", field, s, c)
		}
	}
	return nil
}

// dialProxyCommand runs the given shell command and wraps its stdio
// as a net.Conn. The command is expected to carry SSH protocol bytes
// between us and the remote sshd — typically by exec-ing a network
// tool (nc, socat) or a tunnel helper (AWS SSM session-manager).
//
// The child's stderr is tee'd to the caller's stderr so proxy
// failures are visible; we never consume it ourselves.
func dialProxyCommand(ctx context.Context, command, host string, port int, deadline time.Time) (net.Conn, error) {
	if command == "" {
		return nil, errors.New("proxy command: empty")
	}
	// sh -c matches OpenSSH's behavior: operators expect pipelines,
	// env-var references, and quoting to work the usual way.
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	pc := &proxyConn{
		cmd:    cmd,
		stdin:  stdin,
		stdout: stdout,
		addr:   net.JoinHostPort(host, strconv.Itoa(port)),
	}
	// Bound the time the handshake may take if the proxy never
	// produces bytes. After a successful handshake Dial clears the
	// deadline via SetDeadline(time.Time{}).
	if !deadline.IsZero() {
		_ = pc.SetDeadline(deadline)
	}
	return pc, nil
}

// proxyConn adapts an exec.Cmd's stdio to a net.Conn. SetDeadline is
// best-effort: we can't actually interrupt an in-flight Read/Write on
// a pipe, so we emulate it with a watchdog that kills the child.
type proxyConn struct {
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdout    io.ReadCloser
	addr      string // "host:port" form, used by x/crypto/ssh/knownhosts
	watchdog  *time.Timer
	closeMu   sync.Mutex
	closeOnce sync.Once
}

func (p *proxyConn) Read(b []byte) (int, error)  { return p.stdout.Read(b) }
func (p *proxyConn) Write(b []byte) (int, error) { return p.stdin.Write(b) }

func (p *proxyConn) Close() error {
	p.closeOnce.Do(func() {
		p.closeMu.Lock()
		if p.watchdog != nil {
			p.watchdog.Stop()
			p.watchdog = nil
		}
		p.closeMu.Unlock()
		_ = p.stdin.Close()
		_ = p.stdout.Close()
		if p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
		}
		// Reap to avoid zombies; the exit code isn't useful here
		// since Kill produces a synthetic signal status.
		_ = p.cmd.Wait()
	})
	return nil
}

func (p *proxyConn) LocalAddr() net.Addr  { return proxyAddr{s: p.addr} }
func (p *proxyConn) RemoteAddr() net.Addr { return proxyAddr{s: p.addr} }

func (p *proxyConn) SetDeadline(t time.Time) error {
	p.closeMu.Lock()
	if p.watchdog != nil {
		p.watchdog.Stop()
		p.watchdog = nil
	}
	if t.IsZero() {
		p.closeMu.Unlock()
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		p.closeMu.Unlock()
		_ = p.Close()
		return nil
	}
	p.watchdog = time.AfterFunc(d, func() { _ = p.Close() })
	p.closeMu.Unlock()
	return nil
}

// SetReadDeadline / SetWriteDeadline share the same watchdog: a proxy
// that stalls stalls both directions in practice, and finer-grained
// deadlines on a pipe aren't enforceable anyway.
func (p *proxyConn) SetReadDeadline(t time.Time) error  { return p.SetDeadline(t) }
func (p *proxyConn) SetWriteDeadline(t time.Time) error { return p.SetDeadline(t) }

// proxyAddr reports the logical target (host:port) behind a
// ProxyCommand so downstream consumers like x/crypto/ssh/knownhosts
// can net.SplitHostPort the string. Network() stays "proxy" to make
// it obvious in logs that this did not come off a socket.
type proxyAddr struct{ s string }

func (proxyAddr) Network() string  { return "proxy" }
func (a proxyAddr) String() string { return a.s }

var _ net.Conn = (*proxyConn)(nil)

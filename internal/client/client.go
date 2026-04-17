// Package client implements the gossh SSH client.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oscar/gossh/internal/hostkey"
	"github.com/oscar/gossh/internal/knownhosts"
	"github.com/oscar/gossh/internal/sshcrypto"
)

// Config captures what's needed to connect.
type Config struct {
	Host           string
	Port           int
	User           string
	IdentityFiles  []string
	KnownHostsPath string
	HostCheckMode  knownhosts.Mode
	ConnectTimeout time.Duration
	ClientVersion  string
	// When set, SSH_AUTH_SOCK is ignored. Agent forwarding is never
	// offered — see project design choices in README.
	IgnoreAgent bool
}

// Client is a connected SSH session.
type Client struct {
	conn *ssh.Client
}

// Dial resolves the address and opens an ssh.Client.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Host == "" {
		return nil, errors.New("client: Host required")
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.User == "" {
		u, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("client: resolve local user: %w", err)
		}
		cfg.User = u.Username
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.ClientVersion == "" {
		cfg.ClientVersion = "SSH-2.0-gossh"
	}

	// Host-key verifier.
	if cfg.KnownHostsPath == "" && cfg.HostCheckMode != knownhosts.Off {
		home, _ := os.UserHomeDir()
		cfg.KnownHostsPath = filepath.Join(home, ".ssh", "known_hosts")
	}
	verifier, err := knownhosts.New(cfg.KnownHostsPath, cfg.HostCheckMode)
	if err != nil {
		return nil, fmt.Errorf("client: load known_hosts: %w", err)
	}

	// Identity files.
	signers, err := loadIdentities(cfg.IdentityFiles)
	if err != nil {
		return nil, err
	}
	if len(signers) == 0 {
		return nil, errors.New("client: no identities; pass -i or provide ~/.ssh/id_ed25519")
	}

	clientCfg := &ssh.ClientConfig{
		User:              cfg.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback:   verifier.HostKeyCallback(),
		HostKeyAlgorithms: sshcrypto.HostKeyAlgorithms,
		ClientVersion:     cfg.ClientVersion,
		Timeout:           cfg.ConnectTimeout,
	}
	sshcrypto.ApplyToConfig(&clientCfg.Config)

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))

	// Dial with context so ctx cancel cancels the connect.
	d := net.Dialer{Timeout: cfg.ConnectTimeout}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	// ssh.ClientConfig.Timeout only bounds TCP connect; a server
	// that accepts TCP and then stalls can hang NewClientConn
	// indefinitely. We bound the full handshake (banner + KEX +
	// user-auth) with both a socket deadline and a ctx watcher
	// that closes the socket on cancel.
	handshakeDeadline := time.Now().Add(cfg.ConnectTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(handshakeDeadline) {
		handshakeDeadline = dl
	}
	_ = nc.SetDeadline(handshakeDeadline)
	handshakeDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = nc.Close()
		case <-handshakeDone:
		}
	}()

	hostForVerify := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	sshConn, chans, reqs, err := ssh.NewClientConn(nc, hostForVerify, clientCfg)
	close(handshakeDone)
	if err != nil {
		_ = nc.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("ssh handshake: %w (ctx: %v)", err, ctxErr)
		}
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}
	// Handshake complete — clear the deadline; session I/O should
	// not inherit it.
	_ = nc.SetDeadline(time.Time{})
	return &Client{conn: ssh.NewClient(sshConn, chans, reqs)}, nil
}

// Close tears down the underlying connection.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// Raw returns the underlying *ssh.Client for callers that need to
// extend behavior (e.g., port forwarding). Internal to this repo.
func (c *Client) Raw() *ssh.Client { return c.conn }

// loadIdentities reads one or more private-key files. If paths is
// empty, it probes ~/.ssh/id_ed25519 then ~/.ssh/id_rsa.
func loadIdentities(paths []string) ([]ssh.Signer, error) {
	if len(paths) == 0 {
		home, err := os.UserHomeDir()
		if err == nil {
			for _, n := range []string{"id_ed25519", "id_rsa"} {
				p := filepath.Join(home, ".ssh", n)
				if _, err := os.Stat(p); err == nil {
					paths = append(paths, p)
				}
			}
		}
	}
	var signers []ssh.Signer
	for _, p := range paths {
		kp, err := hostkey.Load(p)
		if err != nil {
			return nil, fmt.Errorf("identity %s: %w", p, err)
		}
		signers = append(signers, kp.Signer)
	}
	return signers, nil
}

// Exec runs command non-interactively, copying stdio between the
// server and the provided streams. Returns the remote exit status.
func (c *Client) Exec(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	return c.ExecContext(context.Background(), command, stdin, stdout, stderr)
}

// ExecContext is like Exec but forwards a single "signal TERM" to the
// remote when ctx is cancelled. Unlike an earlier version, it does
// NOT call signal.Notify — installing a process-wide signal handler
// from a library steals signals from the caller. CLI wrappers should
// install their own handler and cancel ctx.
func (c *Client) ExecContext(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	s, err := c.conn.NewSession()
	if err != nil {
		return -1, err
	}
	defer s.Close()
	s.Stdin = stdin
	s.Stdout = stdout
	s.Stderr = stderr

	if err := s.Start(command); err != nil {
		return -1, err
	}

	// Forward cancellation to the remote as a single SIGTERM. The
	// goroutine exits after delivering once to avoid the earlier
	// bug where it busy-looped on ctx.Done() (which stays closed).
	termed := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			_ = s.Signal(ssh.SIGTERM)
		case <-termed:
		}
	}()
	defer func() {
		close(termed)
		<-done
	}()

	if err := s.Wait(); err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitStatus(), nil
		}
		return -1, err
	}
	return 0, nil
}

// Package server is the sshd implementation.
//
// It focuses on a single-user deployment: the server process runs as
// user U, and authenticated sessions execute commands as U. There is
// no setuid / privilege separation yet.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/exec"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oscar/gossh/internal/authkeys"
	"github.com/oscar/gossh/internal/sshcrypto"
)

// Config is the server configuration.
type Config struct {
	// ListenAddr is the address to bind in "host:port" form. Ignored
	// when Serve is passed a listener directly.
	ListenAddr string

	// HostKeys are the host keys offered to clients, in preference
	// order. At least one is required.
	HostKeys []ssh.Signer

	// ServerVersion is the SSH banner. Defaults to "SSH-2.0-gossh".
	ServerVersion string

	// AuthorizedKeys resolves the set of authorized keys for an
	// inbound user. The returned slice is read-only and may be
	// shared across connections.
	AuthorizedKeys AuthorizedKeysFunc

	// LoginGraceTime is the maximum time a client has to complete
	// authentication. Zero means the library default (120s).
	LoginGraceTime time.Duration

	// MaxAuthTries is the maximum number of public-key offers the
	// server accepts before disconnecting. Defaults to 6.
	MaxAuthTries int

	// Shell is the absolute path of the interactive shell spawned
	// for session "shell" and "pty-req" requests. If empty, the
	// server refuses shell sessions.
	Shell string

	// AllowExec controls whether "exec" session requests are honored.
	AllowExec bool

	// AllowPTY controls whether "pty-req" is honored.
	AllowPTY bool

	// AllowLocalForward controls whether direct-tcpip channels are
	// accepted. When true, remote clients can open outbound TCP
	// connections through this server — treat as a privileged op.
	AllowLocalForward bool

	// AllowRemoteForward controls whether tcpip-forward global
	// requests are accepted, letting clients bind listeners on the
	// server and forward connections back.
	AllowRemoteForward bool

	// Logger receives structured log events. If nil, a discard
	// handler is used.
	Logger *slog.Logger
}

// AuthorizedKeysFunc returns the authorized keys for an SSH login
// name. Returning an empty slice (and nil error) means "no keys
// authorised".
type AuthorizedKeysFunc func(user string) ([]authkeys.Entry, error)

// StaticAuthorizedKeys is a trivial AuthorizedKeysFunc that returns
// the same set of entries for every user.
func StaticAuthorizedKeys(entries []authkeys.Entry) AuthorizedKeysFunc {
	cp := append([]authkeys.Entry(nil), entries...)
	return func(string) ([]authkeys.Entry, error) { return cp, nil }
}

// Server is an instance of gosshd.
type Server struct {
	cfg Config
	log *slog.Logger
}

// New validates the config and returns a Server.
func New(cfg Config) (*Server, error) {
	if len(cfg.HostKeys) == 0 {
		return nil, errors.New("server: at least one host key is required")
	}
	if cfg.AuthorizedKeys == nil {
		return nil, errors.New("server: AuthorizedKeys function is required")
	}
	if cfg.LoginGraceTime == 0 {
		cfg.LoginGraceTime = 120 * time.Second
	}
	if cfg.MaxAuthTries == 0 {
		cfg.MaxAuthTries = 6
	}
	if cfg.ServerVersion == "" {
		cfg.ServerVersion = "SSH-2.0-gossh"
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Server{cfg: cfg, log: log}, nil
}

// ListenAndServe binds cfg.ListenAddr and serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.cfg.ListenAddr == "" {
		return errors.New("server: ListenAddr is empty")
	}
	l, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, l)
}

// Serve accepts connections from the given listener. It returns when
// ctx is cancelled or the listener is closed.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	s.log.Info("listening", "addr", l.Addr().String())
	var wg sync.WaitGroup
	// Close the listener when ctx ends so Accept returns.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			// Temporary accept errors: log and continue.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			wg.Wait()
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) handle(ctx context.Context, nc net.Conn) {
	defer nc.Close()
	remoteStr := nc.RemoteAddr().String()
	log := s.log.With("remote", remoteStr)

	// Enforce a handshake deadline; reset after handshake completes.
	_ = nc.SetDeadline(time.Now().Add(s.cfg.LoginGraceTime))

	sshCfg := s.serverConfig(remoteStr, log)

	conn, chans, reqs, err := ssh.NewServerConn(nc, sshCfg)
	if err != nil {
		log.Info("handshake failed", "err", err)
		return
	}
	// Clear deadline now that we are authenticated.
	_ = nc.SetDeadline(time.Time{})

	defer conn.Close()
	log = log.With("user", conn.User(), "client", string(conn.ClientVersion()))
	log.Info("connected")

	// Spin off global-request handler.
	go s.handleGlobalRequests(ctx, conn, reqs, log)

	// Dispatch channels.
	for newCh := range chans {
		select {
		case <-ctx.Done():
			_ = newCh.Reject(ssh.ResourceShortage, "server shutting down")
			continue
		default:
		}
		switch newCh.ChannelType() {
		case "session":
			go s.handleSession(ctx, conn, newCh, log)
		case "direct-tcpip":
			if !s.cfg.AllowLocalForward {
				_ = newCh.Reject(ssh.Prohibited, "direct-tcpip not permitted")
				continue
			}
			go s.handleDirectTCPIP(ctx, newCh, log)
		default:
			_ = newCh.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

func (s *Server) serverConfig(remoteStr string, log *slog.Logger) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		ServerVersion:           s.cfg.ServerVersion,
		MaxAuthTries:            s.cfg.MaxAuthTries,
		PublicKeyAuthAlgorithms: sshcrypto.PublicKeyAlgorithms,
		// Password / keyboard-interactive are intentionally nil
		// — we only accept public keys.
	}
	sshcrypto.ApplyToConfig(&cfg.Config)
	for _, hk := range s.cfg.HostKeys {
		cfg.AddHostKey(hk)
	}
	cfg.PublicKeyCallback = func(md ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		user := md.User()
		entries, err := s.cfg.AuthorizedKeys(user)
		if err != nil {
			log.Warn("authorized_keys lookup failed", "user", user, "err", err)
			return nil, errors.New("unauthorized")
		}
		entry, err := authkeys.Find(entries, key)
		if err != nil {
			return nil, errors.New("unauthorized")
		}
		// Pass the option set through Permissions.Extensions so the
		// session handler can enforce command=, permitopen=, etc.
		perms := &ssh.Permissions{
			Extensions:      map[string]string{"login-user": user},
			CriticalOptions: map[string]string{},
		}
		if entry.Options.Command != "" {
			perms.CriticalOptions["force-command"] = entry.Options.Command
		}
		// Encode option flags for the session handler.
		encodePermBools(perms, entry.Options)
		log.Info("pubkey authenticated", "user", user, "fp", ssh.FingerprintSHA256(key))
		return perms, nil
	}
	return cfg
}

func encodePermBools(p *ssh.Permissions, o authkeys.Options) {
	setIf := func(k string, v bool) {
		if v {
			p.Extensions[k] = "1"
		}
	}
	setIf("no-port-forwarding", o.NoPortForwarding)
	setIf("no-pty", o.NoPTY)
	setIf("no-agent-forwarding", o.NoAgentForwarding)
	setIf("no-user-rc", o.NoUserRC)
}

// handleGlobalRequests handles requests like tcpip-forward (remote
// port forwarding). For now, we reject all of them unless explicitly
// implemented downstream.
func (s *Server) handleGlobalRequests(ctx context.Context, conn *ssh.ServerConn, reqs <-chan *ssh.Request, log *slog.Logger) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward", "cancel-tcpip-forward":
			if !s.cfg.AllowRemoteForward {
				_ = req.Reply(false, nil)
				continue
			}
			s.handleRemoteForward(ctx, conn, req, log)
		case "keepalive@openssh.com":
			_ = req.Reply(true, nil)
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// ---- handlers below are deliberately stubs; filled in by subsequent commits. ----

// handleRemoteForward is implemented in a later commit (task 9).
func (s *Server) handleRemoteForward(_ context.Context, _ *ssh.ServerConn, req *ssh.Request, _ *slog.Logger) {
	_ = req.Reply(false, nil) // TODO(task 9)
}

// handleDirectTCPIP is implemented in a later commit (task 8).
func (s *Server) handleDirectTCPIP(_ context.Context, newCh ssh.NewChannel, _ *slog.Logger) {
	_ = newCh.Reject(ssh.Prohibited, "direct-tcpip not yet implemented") // TODO(task 8)
}

// handleSession drives a single session channel: exec / shell / pty-req.
// The PTY side (shell + pty-req) is filled in by task 6; here we
// support "exec" for non-interactive commands only.
func (s *Server) handleSession(ctx context.Context, conn *ssh.ServerConn, newCh ssh.NewChannel, log *slog.Logger) {
	ch, reqs, err := newCh.Accept()
	if err != nil {
		log.Warn("session accept failed", "err", err)
		return
	}
	defer ch.Close()

	var (
		env         [][2]string
		ptyReq      *PTYRequest
		wantedShell bool
		execCmd     string
		finished    bool
	)
	forcedCmd := ""
	if conn.Permissions != nil {
		forcedCmd = conn.Permissions.CriticalOptions["force-command"]
	}

	for req := range reqs {
		ok := false
		switch req.Type {
		case "env":
			name, value, perr := parseEnvRequest(req.Payload)
			if perr == nil && isSafeEnvName(name) {
				env = append(env, [2]string{name, value})
				ok = true
			}
		case "pty-req":
			pr, perr := parsePTYReq(req.Payload)
			if perr == nil && s.cfg.AllowPTY && !hasExt(conn, "no-pty") {
				ptyReq = &pr
				ok = true
			}
		case "exec":
			if finished {
				break
			}
			cmd, perr := parseStringRequest(req.Payload)
			if perr != nil {
				break
			}
			if !s.cfg.AllowExec && forcedCmd == "" {
				break
			}
			if forcedCmd != "" {
				// OpenSSH semantics: original command is put in
				// SSH_ORIGINAL_COMMAND for logging; the forced
				// command runs instead.
				env = append(env, [2]string{"SSH_ORIGINAL_COMMAND", cmd})
				execCmd = forcedCmd
			} else {
				execCmd = cmd
			}
			finished = true
			ok = true
		case "shell":
			if finished {
				break
			}
			if s.cfg.Shell == "" {
				break
			}
			if forcedCmd != "" {
				execCmd = forcedCmd
			} else {
				execCmd = "" // empty → interactive shell
				wantedShell = true
			}
			finished = true
			ok = true
		case "window-change":
			if ptyReq != nil {
				pr2, perr := parseWindowChange(req.Payload)
				if perr == nil {
					ptyReq.Rows, ptyReq.Cols = pr2.Rows, pr2.Cols
					ptyReq.Width, ptyReq.Height = pr2.Width, pr2.Height
					ok = true
				}
			}
		case "signal":
			// Best-effort: ignore for now.
			ok = true
		}
		if req.WantReply {
			_ = req.Reply(ok, nil)
		}
		if finished {
			// Dispatch synchronously once we have a command; any
			// further requests on this channel are still handled by
			// the loop (e.g. window-change after shell starts).
			go s.runCommand(ctx, ch, reqs, ptyReq, env, execCmd, wantedShell, log)
			// Continue iterating for post-exec requests like
			// window-change and signal — runCommand also reads from
			// the channel I/O directly.
		}
	}
}

// Helpers below are filled in properly by subsequent tasks. These
// placeholders keep the compiler happy.

func hasExt(conn *ssh.ServerConn, name string) bool {
	if conn.Permissions == nil {
		return false
	}
	return conn.Permissions.Extensions[name] == "1"
}

// runCommand is completed in later tasks for the PTY path. For now,
// it handles the "exec" case.
func (s *Server) runCommand(
	ctx context.Context,
	ch ssh.Channel,
	reqs <-chan *ssh.Request,
	ptyReq *PTYRequest,
	env [][2]string,
	command string,
	wantedShell bool,
	log *slog.Logger,
) {
	_ = reqs // consumed by handleSession's loop
	_ = ptyReq
	_ = wantedShell

	if command == "" {
		// Shell requested but PTY path not ready yet — reject.
		_ = sendExitStatus(ch, 1)
		return
	}

	// Run through the configured shell with -c so quoting matches what
	// OpenSSH does.
	shell := s.cfg.Shell
	if shell == "" {
		shell = "/bin/sh"
	}
	cmd := exec.CommandContext(ctx, shell, "-c", command)
	cmd.Env = envToList(env)
	// Pipe stdin manually so cmd.Wait() does not block on an
	// SSH channel Read that never returns.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintf(ch.Stderr(), "gossh: stdin pipe: %v\n", err)
		_ = sendExitStatus(ch, 127)
		_ = ch.Close()
		return
	}
	cmd.Stdout = ch
	cmd.Stderr = ch.Stderr()

	if err := cmd.Start(); err != nil {
		log.Warn("exec start failed", "err", err)
		fmt.Fprintf(ch.Stderr(), "gossh: %v\n", err)
		_ = sendExitStatus(ch, 127)
		_ = ch.Close()
		return
	}
	// Shovel client stdin into the child. When the channel closes
	// (client sent EOF or we call ch.Close() on the server side),
	// this goroutine exits and the child sees EOF on stdin.
	go func() {
		_, _ = io.Copy(stdin, ch)
		_ = stdin.Close()
	}()
	waitErr := cmd.Wait()
	status := 0
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			status = ee.ExitCode()
			if status < 0 {
				status = 1
			}
		} else {
			status = 1
		}
	}
	_ = ch.CloseWrite()
	_ = sendExitStatus(ch, status)
	_ = ch.Close() // unblocks the Stdin-copy goroutine
}

func envToList(env [][2]string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		out = append(out, kv[0]+"="+kv[1])
	}
	return out
}

func sendExitStatus(ch ssh.Channel, status int) error {
	msg := struct{ Status uint32 }{Status: uint32(status)}
	_, err := ch.SendRequest("exit-status", false, ssh.Marshal(&msg))
	return err
}

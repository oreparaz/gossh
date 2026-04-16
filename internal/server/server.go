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
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
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

	// MaxConnectionsPerIP caps concurrent connections from a single
	// remote IP. Zero means unlimited.
	MaxConnectionsPerIP int

	// ShutdownGrace is the time existing sessions are given to drain
	// after the outer context is cancelled. Zero means "no grace" —
	// cancel immediately propagates to child processes (SIGKILL).
	// A typical value is 10–30s.
	ShutdownGrace time.Duration

	// ClientAliveInterval, if > 0, makes the server send a
	// keepalive request on each idle connection every interval.
	// After ClientAliveCountMax consecutive failures the connection
	// is dropped.
	ClientAliveInterval time.Duration
	ClientAliveCountMax int

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
	cfg     Config
	log     *slog.Logger
	limiter *ipLimiter
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
	return &Server{cfg: cfg, log: log, limiter: newIPLimiter(cfg.MaxConnectionsPerIP)}, nil
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
//
// When ctx is cancelled: the listener is closed immediately (no new
// connections). If ShutdownGrace > 0, existing sessions get that long
// to finish on their own; after the grace period, the inner context
// driving each session is cancelled, which propagates SIGKILL to
// child processes.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	s.log.Info("listening", "addr", l.Addr().String())
	var wg sync.WaitGroup

	// The handler context is used for per-connection state and child
	// processes. We cancel it on shutdown after the grace period; this
	// lets existing SSH sessions drain before we nuke them.
	handleCtx, cancelHandle := context.WithCancel(context.Background())
	defer cancelHandle()

	// Close the listener when ctx ends so Accept returns.
	shutdownOnce := sync.Once{}
	go func() {
		<-ctx.Done()
		_ = l.Close()
		shutdownOnce.Do(func() {
			if s.cfg.ShutdownGrace <= 0 {
				cancelHandle()
				return
			}
			// Grace: cancel only if handlers haven't all finished.
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
				cancelHandle()
			case <-time.After(s.cfg.ShutdownGrace):
				s.log.Warn("shutdown grace expired; killing active sessions")
				cancelHandle()
			}
		})
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			wg.Wait()
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(handleCtx, conn)
		}()
	}
}

func (s *Server) handle(ctx context.Context, nc net.Conn) {
	defer nc.Close()
	remoteStr := nc.RemoteAddr().String()
	log := s.log.With("remote", remoteStr)

	// Per-IP concurrency cap. We reject *after* accept (cannot stop
	// the connect itself), but drop fast.
	release, ok := s.limiter.acquire(nc.RemoteAddr())
	if !ok {
		log.Warn("per-IP connection cap reached; rejecting")
		return
	}
	defer release()

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

	// Per-connection -R forwards registry. Closed when handle returns.
	fwd := newRemoteForwards()
	defer fwd.closeAll()

	// Spin off global-request handler.
	go s.handleGlobalRequests(ctx, conn, fwd, reqs, log)

	// Optional keepalive prober.
	if s.cfg.ClientAliveInterval > 0 {
		max := s.cfg.ClientAliveCountMax
		if max <= 0 {
			max = 3
		}
		probeCtx, probeCancel := context.WithCancel(ctx)
		defer probeCancel()
		go func() {
			t := time.NewTicker(s.cfg.ClientAliveInterval)
			defer t.Stop()
			fails := 0
			for {
				select {
				case <-probeCtx.Done():
					return
				case <-t.C:
					_, _, err := conn.SendRequest("keepalive@openssh.com", true, nil)
					if err != nil {
						fails++
						if fails >= max {
							log.Info("keepalive timed out; closing connection", "fails", fails)
							_ = conn.Close()
							return
						}
					} else {
						fails = 0
					}
				}
			}
		}()
	}

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
			if !s.cfg.AllowLocalForward || hasExt(conn, "no-port-forwarding") {
				_ = newCh.Reject(ssh.Prohibited, "direct-tcpip not permitted")
				continue
			}
			go s.handleDirectTCPIP(ctx, conn, newCh, log)
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
	if len(o.PermitOpen) > 0 {
		parts := make([]string, 0, len(o.PermitOpen))
		for _, hp := range o.PermitOpen {
			parts = append(parts, fmt.Sprintf("%s:%d", hp.Host, hp.Port))
		}
		p.Extensions["permitopen"] = strings.Join(parts, ",")
	}
	if len(o.PermitListen) > 0 {
		parts := make([]string, 0, len(o.PermitListen))
		for _, hp := range o.PermitListen {
			parts = append(parts, fmt.Sprintf("%s:%d", hp.Host, hp.Port))
		}
		p.Extensions["permitlisten"] = strings.Join(parts, ",")
	}
}

// permitOpenFromExt parses the permitopen extension into a slice of
// HostPorts. Empty slice means "no permitopen option in authorized_keys",
// which the caller interprets as "any target allowed".
func permitOpenFromExt(p *ssh.Permissions, key string) []authkeys.HostPort {
	if p == nil || p.Extensions[key] == "" {
		return nil
	}
	raw := strings.Split(p.Extensions[key], ",")
	out := make([]authkeys.HostPort, 0, len(raw))
	for _, r := range raw {
		host, portStr, err := net.SplitHostPort(r)
		if err != nil {
			continue
		}
		var port uint16
		if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
			continue
		}
		out = append(out, authkeys.HostPort{Host: host, Port: port})
	}
	return out
}

// permitOpenAllows reports whether target (host:port) is allowed by
// the permitopen list. An empty list from authorized_keys means the
// key did not restrict forwarding.
func permitOpenAllows(list []authkeys.HostPort, host string, port uint32) bool {
	if len(list) == 0 {
		return true
	}
	for _, hp := range list {
		if hp.Host != "*" && hp.Host != host {
			continue
		}
		if hp.Port != 0 && uint32(hp.Port) != port {
			continue
		}
		return true
	}
	return false
}

// handleGlobalRequests dispatches per-connection global requests.
func (s *Server) handleGlobalRequests(ctx context.Context, conn *ssh.ServerConn, fwd *remoteForwards, reqs <-chan *ssh.Request, log *slog.Logger) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward", "cancel-tcpip-forward":
			if !s.cfg.AllowRemoteForward {
				_ = req.Reply(false, nil)
				continue
			}
			s.doRemoteForward(ctx, conn, fwd, req, log)
		case "keepalive@openssh.com":
			_ = req.Reply(true, nil)
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// handleDirectTCPIP opens a TCP connection to the target in the
// channel-open payload and splices data in both directions. This is
// what powers client-side "-L local_port:target_host:target_port".
func (s *Server) handleDirectTCPIP(ctx context.Context, conn *ssh.ServerConn, newCh ssh.NewChannel, log *slog.Logger) {
	var req struct {
		DestAddr string
		DestPort uint32
		OrigAddr string
		OrigPort uint32
	}
	if err := ssh.Unmarshal(newCh.ExtraData(), &req); err != nil {
		_ = newCh.Reject(ssh.ConnectionFailed, "bad direct-tcpip payload")
		return
	}
	if !permitOpenAllows(permitOpenFromExt(conn.Permissions, "permitopen"), req.DestAddr, req.DestPort) {
		log.Warn("direct-tcpip rejected by permitopen", "dest", req.DestAddr, "port", req.DestPort)
		_ = newCh.Reject(ssh.Prohibited, "target not in permitopen")
		return
	}
	target := net.JoinHostPort(req.DestAddr, fmt.Sprintf("%d", req.DestPort))
	d := net.Dialer{Timeout: 10 * time.Second}
	tcpConn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		log.Info("direct-tcpip dial failed", "target", target, "err", err)
		_ = newCh.Reject(ssh.ConnectionFailed, "dial: "+err.Error())
		return
	}
	ch, reqs, err := newCh.Accept()
	if err != nil {
		_ = tcpConn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	spliceChannel(ch, tcpConn)
	log.Info("direct-tcpip closed", "target", target)
}

// spliceChannel copies bytes in both directions between an SSH channel
// and a net.Conn, closing both when either side finishes.
func spliceChannel(ch ssh.Channel, conn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(ch, conn)
		_ = ch.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, ch)
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
	_ = ch.Close()
	_ = conn.Close()
}

// handleSession drives a single session channel. It collects env and
// pty-req state, then on exec/shell dispatches a runner goroutine and
// pipes subsequent window-change/signal requests to it.
func (s *Server) handleSession(ctx context.Context, conn *ssh.ServerConn, newCh ssh.NewChannel, log *slog.Logger) {
	ch, reqs, err := newCh.Accept()
	if err != nil {
		log.Warn("session accept failed", "err", err)
		return
	}

	state := &sessionState{
		ctx:    ctx,
		server: s,
		conn:   conn,
		ch:     ch,
		log:    log,
		resize: make(chan winSize, 8),
		done:   make(chan struct{}),
	}
	if conn.Permissions != nil {
		state.forcedCmd = conn.Permissions.CriticalOptions["force-command"]
	}

	for req := range reqs {
		state.handleRequest(req)
		if state.started && state.doneReqs {
			break
		}
	}
	// After the request channel closes (or we stopped iterating),
	// wait for any running command to finish before returning.
	if state.started {
		close(state.resize)
		<-state.done
	} else {
		// Nothing ran — close the channel so the client unblocks.
		_ = ch.Close()
	}
}

type sessionState struct {
	ctx    context.Context
	server *Server
	conn   *ssh.ServerConn
	ch     ssh.Channel
	log    *slog.Logger

	env       [][2]string
	ptyReq    *PTYRequest
	forcedCmd string
	started   bool
	doneReqs  bool // set to true when we want to stop reading requests
	resize    chan winSize
	done      chan struct{}

	cmdMu sync.Mutex
	cmd   *exec.Cmd
}

// setChildCmd stores the running child so "signal" requests can
// deliver POSIX signals while the session is live. cleared via nil.
func (st *sessionState) setChildCmd(c *exec.Cmd) {
	st.cmdMu.Lock()
	st.cmd = c
	st.cmdMu.Unlock()
}

// deliverSignal resolves an RFC-4254 signal name to a POSIX signal and
// forwards it to the running child. No-op if no child is running.
func (st *sessionState) deliverSignal(name string) bool {
	st.cmdMu.Lock()
	c := st.cmd
	st.cmdMu.Unlock()
	if c == nil || c.Process == nil {
		return false
	}
	sig, ok := posixSignal(name)
	if !ok {
		return false
	}
	_ = c.Process.Signal(sig)
	return true
}

func posixSignal(name string) (syscall.Signal, bool) {
	switch name {
	case "ABRT":
		return syscall.SIGABRT, true
	case "ALRM":
		return syscall.SIGALRM, true
	case "FPE":
		return syscall.SIGFPE, true
	case "HUP":
		return syscall.SIGHUP, true
	case "ILL":
		return syscall.SIGILL, true
	case "INT":
		return syscall.SIGINT, true
	case "KILL":
		return syscall.SIGKILL, true
	case "PIPE":
		return syscall.SIGPIPE, true
	case "QUIT":
		return syscall.SIGQUIT, true
	case "SEGV":
		return syscall.SIGSEGV, true
	case "TERM":
		return syscall.SIGTERM, true
	case "USR1":
		return syscall.SIGUSR1, true
	case "USR2":
		return syscall.SIGUSR2, true
	}
	return 0, false
}

type winSize struct{ Rows, Cols, Width, Height uint32 }

func (st *sessionState) handleRequest(req *ssh.Request) {
	ok := false
	switch req.Type {
	case "env":
		name, value, perr := parseEnvRequest(req.Payload)
		if perr == nil && isSafeEnvName(name) {
			st.env = append(st.env, [2]string{name, value})
			ok = true
		}
	case "pty-req":
		if st.server.cfg.AllowPTY && !hasExt(st.conn, "no-pty") {
			pr, perr := parsePTYReq(req.Payload)
			if perr == nil {
				st.ptyReq = &pr
				ok = true
			}
		}
	case "exec":
		if !st.started {
			cmd, perr := parseStringRequest(req.Payload)
			if perr == nil {
				cmdline := cmd
				if st.forcedCmd != "" {
					st.env = append(st.env, [2]string{"SSH_ORIGINAL_COMMAND", cmd})
					cmdline = st.forcedCmd
				}
				if st.server.cfg.AllowExec || st.forcedCmd != "" {
					st.started = true
					ok = true
					go st.run(cmdline, false)
				}
			}
		}
	case "shell":
		if !st.started && st.server.cfg.Shell != "" {
			cmdline := ""
			if st.forcedCmd != "" {
				cmdline = st.forcedCmd
			}
			st.started = true
			ok = true
			go st.run(cmdline, true)
		}
	case "window-change":
		if st.ptyReq != nil {
			pr, perr := parseWindowChange(req.Payload)
			if perr == nil {
				select {
				case st.resize <- winSize{Rows: pr.Rows, Cols: pr.Cols, Width: pr.Width, Height: pr.Height}:
				default:
				}
				ok = true
			}
		}
	case "signal":
		name, perr := parseStringRequest(req.Payload)
		if perr == nil && st.deliverSignal(name) {
			ok = true
		}
	}
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

// run dispatches to the exec or PTY runner and signals completion.
func (st *sessionState) run(command string, wantShell bool) {
	defer close(st.done)
	if st.ptyReq != nil {
		st.runPTY(command, wantShell)
		return
	}
	if wantShell && command == "" {
		// A "shell" request without pty-req: start an interactive
		// shell piped through the channel. Some clients do this when
		// invoked with -T.
		st.runPipe(st.server.cfg.Shell, nil)
		return
	}
	st.runPipe(st.server.cfg.Shell, []string{"-c", command})
}

func hasExt(conn *ssh.ServerConn, name string) bool {
	if conn.Permissions == nil {
		return false
	}
	return conn.Permissions.Extensions[name] == "1"
}

// runPipe runs cmd with its stdio plumbed over the SSH channel.
// Use this when no PTY was requested.
func (st *sessionState) runPipe(shell string, args []string) {
	if shell == "" {
		shell = "/bin/sh"
	}
	cmd := exec.CommandContext(st.ctx, shell, args...)
	cmd.Env = st.finalEnv(false)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintf(st.ch.Stderr(), "gossh: stdin pipe: %v\n", err)
		_ = sendExitStatus(st.ch, 127)
		_ = st.ch.Close()
		return
	}
	cmd.Stdout = st.ch
	cmd.Stderr = st.ch.Stderr()
	if err := cmd.Start(); err != nil {
		st.log.Warn("exec start failed", "err", err)
		fmt.Fprintf(st.ch.Stderr(), "gossh: %v\n", err)
		_ = sendExitStatus(st.ch, 127)
		_ = st.ch.Close()
		return
	}
	st.setChildCmd(cmd)
	defer st.setChildCmd(nil)
	go func() {
		_, _ = io.Copy(stdin, st.ch)
		_ = stdin.Close()
	}()
	waitErr := cmd.Wait()
	_ = st.ch.CloseWrite()
	_ = sendExitStatus(st.ch, exitStatus(waitErr))
	_ = st.ch.Close()
}

func exitStatus(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ee.ExitCode() >= 0 {
			return ee.ExitCode()
		}
		// Killed by signal — report 128+signum like a shell would.
		if ws, ok := ee.Sys().(interface{ Signal() os.Signal }); ok {
			if sig, ok := ws.Signal().(syscall.Signal); ok {
				return 128 + int(sig)
			}
		}
		return 1
	}
	return 1
}

func (st *sessionState) finalEnv(isPTY bool) []string {
	base := append([]string(nil),
		"HOME="+os.Getenv("HOME"),
		"USER="+os.Getenv("USER"),
		"LOGNAME="+os.Getenv("USER"),
		"SHELL="+st.server.cfg.Shell,
		"PATH="+osPath(),
	)
	if isPTY && st.ptyReq != nil && st.ptyReq.Term != "" {
		base = append(base, "TERM="+st.ptyReq.Term)
	}
	if addr, ok := st.conn.RemoteAddr().(*net.TCPAddr); ok {
		// SSH_CONNECTION format: client_ip client_port server_ip server_port
		local, _ := st.conn.LocalAddr().(*net.TCPAddr)
		lip, lp := "", 0
		if local != nil {
			lip, lp = local.IP.String(), local.Port
		}
		base = append(base, fmt.Sprintf("SSH_CONNECTION=%s %d %s %d", addr.IP, addr.Port, lip, lp))
	}
	// Client-provided env on top (filtered in isSafeEnvName).
	for _, kv := range st.env {
		base = append(base, kv[0]+"="+kv[1])
	}
	return base
}

func osPath() string {
	if p := os.Getenv("PATH"); p != "" {
		return p
	}
	return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
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

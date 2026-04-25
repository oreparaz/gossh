// Command gosshd is a minimal sshd replacement.
//
// Usage:
//
//	gosshd -listen :2222 \
//	       -host-key /etc/gossh/host_ed25519 \
//	       -authorized-keys /etc/gossh/authorized_keys \
//	       -shell /bin/bash
//
// A missing host key is generated on first start (Ed25519).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oreparaz/gossh/internal/audit"
	"github.com/oreparaz/gossh/internal/authkeys"
	"github.com/oreparaz/gossh/internal/cliutil"
	"github.com/oreparaz/gossh/internal/hostkey"
	"github.com/oreparaz/gossh/internal/server"
	"github.com/oreparaz/gossh/internal/sshconfig"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gosshd:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listen       = flag.String("listen", "0.0.0.0:2222", "address to listen on")
		hostKeyPaths cliutil.MultiFlag
		authKeysPath = flag.String("authorized-keys", "", "path to authorized_keys file (required)")
		shell        = flag.String("shell", "/bin/bash", "shell to launch for interactive sessions")
		allowExec    = flag.Bool("allow-exec", true, "accept 'exec' requests")
		allowPTY     = flag.Bool("allow-pty", true, "accept PTY allocation")
		allowLF      = flag.Bool("allow-local-forward", false, "accept direct-tcpip channels (-L)")
		allowRF      = flag.Bool("allow-remote-forward", false, "accept tcpip-forward requests (-R)")
		loginGrace   = flag.Duration("login-grace", 120*time.Second, "max time to complete authentication")
		maxAuth      = flag.Int("max-auth-tries", 6, "max public-key offers before disconnect")
		maxPerIP     = flag.Int("max-per-ip", 10, "concurrent connections per remote IP (0 = unlimited)")
		maxConns     = flag.Int("max-connections", 0, "global concurrent connections cap (0 = unlimited)")
		shutdownGr   = flag.Duration("shutdown-grace", 10*time.Second, "on SIGTERM, wait this long for sessions to drain before killing them")
		kaInterval   = flag.Duration("client-alive-interval", 0, "send keepalive every N if idle (0 disables)")
		kaCount      = flag.Int("client-alive-count-max", 3, "disconnect after this many consecutive keepalive failures")
		auditPath    = flag.String("audit-log", "", "append JSON-lines audit events to this file (0600)")
		auditFsync   = flag.Bool("audit-fsync", false, "fsync after every audit event (expensive, safer)")
		configPath   = flag.String("f", "", "path to sshd_config (CLI flags override file values)")
		verbose      = flag.Bool("v", false, "verbose logging")
	)
	flag.Var(&hostKeyPaths, "host-key", "path to host key file (repeatable); ed25519 is generated if missing")
	flag.Parse()

	// Apply sshd_config values as defaults before CLI overrides.
	if *configPath != "" {
		sc, err := sshconfig.ParseServerFile(*configPath)
		if err != nil {
			return fmt.Errorf("sshd_config: %w", err)
		}
		if *authKeysPath == "" && sc.AuthorizedKeysFile != "" {
			*authKeysPath = sc.AuthorizedKeysFile
		}
		if len(hostKeyPaths) == 0 && len(sc.HostKeys) > 0 {
			hostKeyPaths = append(hostKeyPaths, sc.HostKeys...)
		}
		if sc.MaxAuthTries != 0 && !cliutil.FlagSet("max-auth-tries") {
			*maxAuth = sc.MaxAuthTries
		}
		if sc.PasswordAuthentication {
			return errors.New("sshd_config: PasswordAuthentication yes is not supported; remove it to proceed")
		}
		switch strings.ToLower(sc.PermitRootLogin) {
		case "", "no", "prohibit-password":
			// OK: prohibit-password is equivalent to our pubkey-only posture.
		case "yes":
			// Allowed, but surface a warning on stderr (log isn't set up yet).
			fmt.Fprintln(os.Stderr, "gosshd: warning: PermitRootLogin yes is advisory — gosshd does not map SSH users to system uids")
		default:
			return fmt.Errorf("sshd_config: unsupported PermitRootLogin %q", sc.PermitRootLogin)
		}
		// Apply sshd_config Port only when the operator didn't pass
		// -listen. Rewriting the host:port pair preserves any -listen
		// bind address; bare port from config replaces just the port.
		if sc.Port != 0 && !cliutil.FlagSet("listen") {
			host, _, herr := net.SplitHostPort(*listen)
			if herr != nil {
				// Default "0.0.0.0:2222" splits cleanly, so this
				// path is only reachable if someone changed the
				// default to something SplitHostPort can't handle.
				host = "0.0.0.0"
			}
			*listen = net.JoinHostPort(host, strconv.Itoa(sc.Port))
		}
	}

	if *authKeysPath == "" {
		return errors.New("-authorized-keys is required")
	}
	if len(hostKeyPaths) == 0 {
		// Sensible default: ./host_ed25519 next to the binary.
		hostKeyPaths = cliutil.MultiFlag{"./host_ed25519"}
	}

	lvl := slog.LevelInfo
	if *verbose {
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	var signers []ssh.Signer
	for _, p := range hostKeyPaths {
		kp, err := hostkey.LoadOrGenerate(p, hostkey.Ed25519, 0, "gosshd host key")
		if err != nil {
			return fmt.Errorf("host key %s: %w", p, err)
		}
		signers = append(signers, kp.Signer)
		log.Info("host key loaded", "path", p, "type", kp.Signer.PublicKey().Type(), "fp", ssh.FingerprintSHA256(kp.Signer.PublicKey()))
	}

	// Validate once at startup so misconfiguration fails fast.
	if _, err := authkeys.ParseFile(*authKeysPath); err != nil {
		return fmt.Errorf("authorized_keys: %w", err)
	}

	var auditLog audit.Logger = audit.Nop
	if *auditPath != "" {
		f, err := audit.OpenFile(*auditPath)
		if err != nil {
			return fmt.Errorf("open audit log %s: %w", *auditPath, err)
		}
		defer f.Close()
		// Surface audit write/fsync failures via the regular logger
		// so operators notice disk-full / permissions issues even
		// though Emit itself has no return value.
		auditLog = &audit.JSONLogger{
			Writer: f,
			Fsync:  *auditFsync,
			OnError: func(err error, eventType string) {
				log.Error("audit log write failed", "event", eventType, "err", err)
			},
		}
	}

	cfg := server.Config{
		ListenAddr: *listen,
		HostKeys:   signers,
		// Always reload on mtime change — a revoked key must stop
		// working without a server restart. There is no operator
		// value in a "static, never reload" mode.
		AuthorizedKeys:      server.ReloadingAuthorizedKeys(*authKeysPath),
		Shell:               *shell,
		AllowExec:           *allowExec,
		AllowPTY:            *allowPTY,
		AllowLocalForward:   *allowLF,
		AllowRemoteForward:  *allowRF,
		LoginGraceTime:      *loginGrace,
		MaxAuthTries:        *maxAuth,
		MaxConnectionsPerIP: *maxPerIP,
		MaxConnections:      *maxConns,
		ShutdownGrace:       *shutdownGr,
		ClientAliveInterval: *kaInterval,
		ClientAliveCountMax: *kaCount,
		Logger:              log,
		Audit:               auditLog,
	}

	s, err := server.New(cfg)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return s.ListenAndServe(ctx)
}

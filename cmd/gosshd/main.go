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
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oscar/gossh/internal/authkeys"
	"github.com/oscar/gossh/internal/hostkey"
	"github.com/oscar/gossh/internal/server"
	"github.com/oscar/gossh/internal/sshconfig"
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
		hostKeyPaths multiFlag
		authKeysPath = flag.String("authorized-keys", "", "path to authorized_keys file (required)")
		shell        = flag.String("shell", "/bin/bash", "shell to launch for interactive sessions")
		allowExec    = flag.Bool("allow-exec", true, "accept 'exec' requests")
		allowPTY     = flag.Bool("allow-pty", true, "accept PTY allocation")
		allowLF      = flag.Bool("allow-local-forward", false, "accept direct-tcpip channels (-L)")
		allowRF      = flag.Bool("allow-remote-forward", false, "accept tcpip-forward requests (-R)")
		loginGrace   = flag.Duration("login-grace", 120*time.Second, "max time to complete authentication")
		maxAuth      = flag.Int("max-auth-tries", 6, "max public-key offers before disconnect")
		maxPerIP     = flag.Int("max-per-ip", 10, "concurrent connections per remote IP (0 = unlimited)")
		shutdownGr   = flag.Duration("shutdown-grace", 10*time.Second, "on SIGTERM, wait this long for sessions to drain before killing them")
		kaInterval   = flag.Duration("client-alive-interval", 0, "send keepalive every N if idle (0 disables)")
		kaCount      = flag.Int("client-alive-count-max", 3, "disconnect after this many consecutive keepalive failures")
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
		if sc.MaxAuthTries != 0 && !flagSet("max-auth-tries") {
			*maxAuth = sc.MaxAuthTries
		}
		if sc.Port != 0 && !flagSet("listen") {
			// Rewrite listen to use configured port if we're on the default.
			if strings.HasSuffix(*listen, ":2222") {
				*listen = strings.TrimSuffix(*listen, ":2222") + fmt.Sprintf(":%d", sc.Port)
			}
		}
		if sc.PasswordAuthentication {
			return errors.New("sshd_config: PasswordAuthentication yes is not supported; remove it to proceed")
		}
	}

	if *authKeysPath == "" {
		return errors.New("-authorized-keys is required")
	}
	if len(hostKeyPaths) == 0 {
		// Sensible default: ./host_ed25519 next to the binary.
		hostKeyPaths = multiFlag{"./host_ed25519"}
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

	entries, err := authkeys.ParseFile(*authKeysPath)
	if err != nil {
		return fmt.Errorf("authorized_keys: %w", err)
	}

	cfg := server.Config{
		ListenAddr:          *listen,
		HostKeys:            signers,
		AuthorizedKeys:      server.StaticAuthorizedKeys(entries),
		Shell:               *shell,
		AllowExec:           *allowExec,
		AllowPTY:            *allowPTY,
		AllowLocalForward:   *allowLF,
		AllowRemoteForward:  *allowRF,
		LoginGraceTime:      *loginGrace,
		MaxAuthTries:        *maxAuth,
		MaxConnectionsPerIP: *maxPerIP,
		ShutdownGrace:       *shutdownGr,
		ClientAliveInterval: *kaInterval,
		ClientAliveCountMax: *kaCount,
		Logger:              log,
	}

	s, err := server.New(cfg)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return s.ListenAndServe(ctx)
}

type multiFlag []string

func (m *multiFlag) String() string     { return fmt.Sprintf("%v", []string(*m)) }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

func flagSet(name string) bool {
	seen := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			seen = true
		}
	})
	return seen
}

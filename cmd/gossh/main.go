// Command gossh is a minimal ssh-compatible client.
//
// Usage:
//
//	gossh [flags] [user@]host[:port] [command...]
//
// Flags are a small subset of openssh-client: -i, -p, -l, -L, -R, -D,
// -T, -t, -o StrictHostKeyChecking, -N, -v.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/oscar/gossh/internal/client"
	"github.com/oscar/gossh/internal/forward"
	"github.com/oscar/gossh/internal/knownhosts"
	"github.com/oscar/gossh/internal/sshconfig"
)

func main() {
	code, err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gossh:", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

type multiFlag []string

func (m *multiFlag) String() string     { return fmt.Sprintf("%v", []string(*m)) }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

func run() (int, error) {
	var (
		port          = flag.Int("p", 22, "remote port")
		login         = flag.String("l", "", "remote username (overrides user@host)")
		identities    multiFlag
		locals        multiFlag
		remotes       multiFlag
		dynamics      multiFlag
		forceTTY      = flag.Bool("t", false, "force PTY allocation")
		disableTTY    = flag.Bool("T", false, "disable PTY allocation")
		noCommand     = flag.Bool("N", false, "do not execute a remote command (useful for forwarding)")
		strict        = flag.String("strict-host-key", "yes", "yes (refuse unknown hosts, the safe default), accept-new (TOFU), no (disable entirely)")
		knownHostsArg = flag.String("known-hosts", "", "override known_hosts path")
		configPath    = flag.String("F", "", "path to ssh_config (values override defaults, CLI overrides file)")
	)
	flag.Var(&identities, "i", "path to identity file (repeatable)")
	flag.Var(&locals, "L", "local forward: [bind:]port:host:hostport (repeatable)")
	flag.Var(&remotes, "R", "remote forward: [bind:]port:host:hostport (repeatable)")
	flag.Var(&dynamics, "D", "dynamic SOCKS5 forward: [bind:]port (repeatable)")
	flag.Parse()

	if flag.NArg() < 1 {
		return 2, errors.New("usage: gossh [flags] [user@]host[:port] [command...]")
	}
	target := flag.Arg(0)
	user, host, remotePort, err := parseTarget(target, *port)
	if err != nil {
		return 2, err
	}

	// Apply ssh_config values before CLI overrides.
	var cfgHost sshconfig.ClientHost
	if *configPath != "" {
		cc, err := sshconfig.ParseClientFile(*configPath)
		if err != nil {
			return 2, fmt.Errorf("ssh_config: %w", err)
		}
		cfgHost = cc.ResolveHost(host)
	}

	// Host alias resolution: ssh_config "Host alias"/"Hostname realhost".
	if cfgHost.Hostname != "" && cfgHost.Hostname != host {
		host = cfgHost.Hostname
	}
	if cfgHost.Port != 0 && *port == 22 {
		remotePort = cfgHost.Port
	}
	if user == "" && cfgHost.User != "" {
		user = cfgHost.User
	}
	if *login != "" {
		user = *login
	}
	// Identity files: CLI wins; otherwise use file entries.
	if len(identities) == 0 && len(cfgHost.IdentityFiles) > 0 {
		identities = append(multiFlag(nil), cfgHost.IdentityFiles...)
	}
	// Strict host key checking: CLI explicit wins over file.
	strictVal := *strict
	if cfgHost.StrictHost != "" && !explicitStrict(strict) {
		strictVal = cfgHost.StrictHost
	}
	knownHostsVal := *knownHostsArg
	if knownHostsVal == "" && cfgHost.KnownHosts != "" {
		knownHostsVal = cfgHost.KnownHosts
	}

	mode, err := parseStrict(strictVal)
	if err != nil {
		return 2, err
	}

	cfg := client.Config{
		Host:           host,
		Port:           remotePort,
		User:           user,
		IdentityFiles:  identities,
		KnownHostsPath: knownHostsVal,
		HostCheckMode:  mode,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	c, err := client.Dial(ctx, cfg)
	if err != nil {
		return 255, err
	}
	defer c.Close()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	// Set up forwardings.
	var stops []func()
	for _, spec := range locals {
		s, err := forward.ParseLocal(spec)
		if err != nil {
			return 2, fmt.Errorf("-L %s: %w", spec, err)
		}
		stop, err := forward.Local(ctx, c.Raw(), s, log)
		if err != nil {
			return 255, err
		}
		stops = append(stops, stop)
	}
	for _, spec := range remotes {
		s, err := forward.ParseLocal(spec)
		if err != nil {
			return 2, fmt.Errorf("-R %s: %w", spec, err)
		}
		stop, err := forward.Remote(ctx, c.Raw(), s, log)
		if err != nil {
			return 255, err
		}
		stops = append(stops, stop)
	}
	for _, spec := range dynamics {
		s, err := forward.ParseDynamic(spec)
		if err != nil {
			return 2, fmt.Errorf("-D %s: %w", spec, err)
		}
		stop, err := forward.Dynamic(ctx, c.Raw(), s, log)
		if err != nil {
			return 255, err
		}
		stops = append(stops, stop)
	}
	defer func() {
		for _, s := range stops {
			s()
		}
	}()

	if *noCommand {
		// Block until either the local signal cancels ctx or the
		// SSH connection dies. Previously we only watched ctx, so a
		// remote disconnect left gossh hung until the user killed it.
		connErr := make(chan error, 1)
		go func() { connErr <- c.Raw().Wait() }()
		select {
		case <-ctx.Done():
			return 0, nil
		case err := <-connErr:
			if err != nil {
				return 255, fmt.Errorf("connection lost: %w", err)
			}
			return 0, nil
		}
	}

	remoteArgs := flag.Args()[1:]

	switch {
	case len(remoteArgs) == 0 && !*disableTTY:
		status, err := c.Shell()
		return status, err
	case *forceTTY:
		status, err := c.ExecInteractive(strings.Join(remoteArgs, " "))
		return status, err
	default:
		// ExecContext forwards ctx cancellation as a "signal TERM"
		// to the remote so Ctrl-C (which cancels ctx via
		// NotifyContext above) terminates the remote command.
		status, err := c.ExecContext(ctx, strings.Join(remoteArgs, " "), os.Stdin, os.Stdout, os.Stderr)
		return status, err
	}
}

func parseTarget(s string, defPort int) (user, host string, port int, err error) {
	port = defPort
	// user@host[:port]
	if at := strings.LastIndex(s, "@"); at >= 0 {
		user = s[:at]
		s = s[at+1:]
	}
	// IPv6 bracketed?
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", "", 0, fmt.Errorf("unterminated IPv6 bracket in %q", s)
		}
		host = s[1:end]
		rest := s[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return "", "", 0, fmt.Errorf("unexpected %q after IPv6", rest)
			}
			p, perr := strconv.Atoi(rest[1:])
			if perr != nil {
				return "", "", 0, fmt.Errorf("bad port %q", rest[1:])
			}
			port = p
		}
		return user, host, port, nil
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		host = s[:i]
		p, perr := strconv.Atoi(s[i+1:])
		if perr != nil {
			return "", "", 0, fmt.Errorf("bad port %q", s[i+1:])
		}
		port = p
	} else {
		host = s
	}
	return user, host, port, nil
}

// explicitStrict reports whether the user set -strict-host-key on the
// command line (vs. leaving the default in place).
func explicitStrict(p *string) bool {
	seen := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "strict-host-key" {
			seen = true
		}
	})
	return seen
}

func parseStrict(v string) (knownhosts.Mode, error) {
	switch v {
	case "yes", "ask", "strict":
		return knownhosts.Strict, nil
	case "accept-new", "":
		return knownhosts.AcceptNew, nil
	case "no", "off":
		return knownhosts.Off, nil
	default:
		return 0, fmt.Errorf("unknown strict-host-key %q", v)
	}
}

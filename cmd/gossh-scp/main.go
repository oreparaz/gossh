// Command gossh-scp is a minimal SCP client for transferring files
// and directory trees over an SSH connection provided by the gossh
// client package.
//
// Usage:
//
//	gossh-scp [flags] localpath   [user@]host[:port]:remotepath
//	gossh-scp [flags] [user@]host[:port]:remotepath localpath
//
// Pass -r to recursively copy directories. One argument contains a
// colon (the remote); the other is local. Recursive transfers are
// depth-capped and every remote filename goes through the same
// CVE-hardened validator as single-file transfers; see the scp
// package for details.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/oscar/gossh/internal/client"
	"github.com/oscar/gossh/internal/cliutil"
	"github.com/oscar/gossh/internal/scp"
	"github.com/oscar/gossh/internal/sshconfig"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gossh-scp:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		port          = flag.Int("p", 22, "remote port")
		login         = flag.String("l", "", "remote username (overrides user@host)")
		identities    cliutil.MultiFlag
		strictArg     = flag.String("strict-host-key", "yes", "yes (default, refuse unknown) | accept-new (TOFU)")
		knownHostsArg = flag.String("known-hosts", "", "override known_hosts path")
		configPath    = flag.String("F", "", "path to ssh_config (default: ~/.ssh/config if present)")
		connTimeout   = flag.Duration("connect-timeout", 10*time.Second, "")
		recursive     = flag.Bool("r", false, "recursively copy directory trees")
		proxyCmd      = flag.String("proxy-command", "", "ProxyCommand: shell command to tunnel the SSH transport (supports %h/%p/%r)")
	)
	flag.Var(&identities, "i", "path to identity file (repeatable)")
	flag.Parse()

	if flag.NArg() != 2 {
		return errors.New("usage: gossh-scp [flags] SRC DST   (one of SRC/DST contains a colon)")
	}
	src, dst := flag.Arg(0), flag.Arg(1)

	srcRemote, srcBody := splitRemote(src)
	dstRemote, dstBody := splitRemote(dst)
	if srcRemote == "" && dstRemote == "" {
		return errors.New("neither path is remote; use cp(1)")
	}
	if srcRemote != "" && dstRemote != "" {
		return errors.New("remote-to-remote transfers are not supported")
	}

	var (
		target string
		upload bool
		local  string
		remote string
	)
	if dstRemote != "" {
		upload = true
		target = dstRemote
		local = srcBody
		remote = dstBody
	} else {
		target = srcRemote
		local = dstBody
		remote = srcBody
	}

	user, host, remotePort, portExplicit, err := cliutil.ParseTarget(target, *port)
	if err != nil {
		return err
	}
	portFromUser := portExplicit || cliutil.FlagSet("p")

	// ssh_config: auto-load ~/.ssh/config unless -F overrides.
	configFile := *configPath
	if configFile == "" {
		if home, herr := os.UserHomeDir(); herr == nil {
			candidate := home + "/.ssh/config"
			if _, statErr := os.Stat(candidate); statErr == nil {
				configFile = candidate
			}
		}
	}
	var cfgHost sshconfig.ClientHost
	if configFile != "" {
		cc, cerr := sshconfig.ParseClientFile(configFile)
		if cerr != nil {
			return fmt.Errorf("ssh_config: %w", cerr)
		}
		cfgHost = cc.ResolveHost(host)
	}
	if cfgHost.Hostname != "" && cfgHost.Hostname != host {
		host = cfgHost.Hostname
	}
	if cfgHost.Port != 0 && !portFromUser {
		remotePort = cfgHost.Port
	}
	if user == "" && cfgHost.User != "" {
		user = cfgHost.User
	}
	if *login != "" {
		user = *login
	}
	if len(identities) == 0 && len(cfgHost.IdentityFiles) > 0 {
		identities = append(cliutil.MultiFlag(nil), cfgHost.IdentityFiles...)
	}
	knownHostsVal := *knownHostsArg
	if knownHostsVal == "" && cfgHost.KnownHosts != "" {
		knownHostsVal = cfgHost.KnownHosts
	}
	strictVal := *strictArg
	if cfgHost.StrictHost != "" && !cliutil.FlagSet("strict-host-key") {
		strictVal = cfgHost.StrictHost
	}
	proxyCmdVal := *proxyCmd
	if proxyCmdVal == "" && cfgHost.ProxyCommand != "" {
		proxyCmdVal = cfgHost.ProxyCommand
	}

	mode, err := cliutil.ParseStrictHostKey(strictVal)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	c, err := client.Dial(ctx, client.Config{
		Host:           host,
		Port:           remotePort,
		User:           user,
		IdentityFiles:  identities,
		KnownHostsPath: knownHostsVal,
		HostCheckMode:  mode,
		ConnectTimeout: *connTimeout,
		ProxyCommand:   proxyCmdVal,
	})
	if err != nil {
		return err
	}
	defer c.Close()

	if upload {
		return scp.Upload(c.Raw(), local, remote, *recursive)
	}
	return scp.Download(c.Raw(), remote, local, *recursive)
}

// splitRemote splits a `[user@]host[:port]:path` SCP argument into
// (remote, path), where `remote` is the `[user@]host[:port]` prefix
// in a form ParseTarget accepts. If s has no remote component,
// returns ("", s). IPv6 hosts use `[addr]` bracketed form and may or
// may not include a user@ prefix; the bracket + colon logic runs
// AFTER any user@ is peeled off, so `alice@[::1]:/tmp/x` parses.
func splitRemote(s string) (remote, path string) {
	userPrefix := ""
	if at := strings.LastIndex(s, "@"); at >= 0 {
		// Preserve the user@ so ParseTarget sees the whole token,
		// but do bracket scanning on the host portion only.
		userPrefix = s[:at+1]
		s = s[at+1:]
	}
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", userPrefix + s
		}
		// [ipv6]:rest — rest is either :path or :port:path
		rest := s[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", userPrefix + s
		}
		// Look past the first ':' — if there's another ':' before
		// the path separator's typical content, the token between
		// them is a port. But SCP grammar is `[host]:port:path`, so
		// the second ':' terminates the port.
		pathIdx := strings.Index(rest[1:], ":")
		if pathIdx < 0 {
			// [ipv6]:path
			return userPrefix + s[:end+1], rest[1:]
		}
		// [ipv6]:port:path
		return userPrefix + s[:end+1+1+pathIdx], rest[1+pathIdx+1:]
	}
	i := strings.Index(s, ":")
	if i < 0 {
		return "", userPrefix + s
	}
	return userPrefix + s[:i], s[i+1:]
}

// Command gossh-scp is a minimal SCP client for transferring single
// files over an SSH connection provided by the gossh client package.
//
// Usage:
//
//	gossh-scp [flags] localfile   [user@]host[:port]:remotepath
//	gossh-scp [flags] [user@]host[:port]:remotepath localfile
//
// One argument contains a colon (the remote); the other is local.
// Recursion (-r) is not supported — SCP's historical vulnerabilities
// live almost entirely in its directory-walk code. For bulk / tree
// copy, tar over `gossh host 'tar -cz ...'`.
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

	user, host, remotePort, err := cliutil.ParseTarget(target, *port)
	if err != nil {
		return err
	}

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
	if cfgHost.Port != 0 && *port == 22 {
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

// splitRemote: if s contains a colon outside an IPv6 bracket, split
// off the "host[:port]" prefix from the path suffix.
func splitRemote(s string) (remote, path string) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", s
		}
		// [ipv6]:rest — everything until the first ':' after ']'
		rest := s[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", s
		}
		// s = [ipv6]:path OR [ipv6]:port:path
		pathIdx := strings.Index(rest[1:], ":")
		if pathIdx < 0 {
			return s[:end+1], rest[1:]
		}
		return s[:end+1+1+pathIdx], rest[1+pathIdx+1:]
	}
	i := strings.Index(s, ":")
	if i < 0 {
		return "", s
	}
	return s[:i], s[i+1:]
}

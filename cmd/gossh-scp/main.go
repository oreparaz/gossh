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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oscar/gossh/internal/client"
	"github.com/oscar/gossh/internal/knownhosts"
	"github.com/oscar/gossh/internal/scp"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gossh-scp:", err)
		os.Exit(1)
	}
}

type multiFlag []string

func (m *multiFlag) String() string     { return fmt.Sprintf("%v", []string(*m)) }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

func run() error {
	var (
		port          = flag.Int("p", 22, "remote port")
		login         = flag.String("l", "", "remote username (overrides user@host)")
		identities    multiFlag
		strictArg     = flag.String("strict-host-key", "yes", "yes (default, refuse unknown) | accept-new (TOFU) | no (disable)")
		knownHostsArg = flag.String("known-hosts", "", "override known_hosts path")
		connTimeout   = flag.Duration("connect-timeout", 10*time.Second, "")
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

	user, host, remotePort, err := parseTarget(target, *port)
	if err != nil {
		return err
	}
	if *login != "" {
		user = *login
	}

	mode, err := parseStrict(*strictArg)
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
		KnownHostsPath: *knownHostsArg,
		HostCheckMode:  mode,
		ConnectTimeout: *connTimeout,
	})
	if err != nil {
		return err
	}
	defer c.Close()

	if upload {
		return scp.Upload(c.Raw(), local, remote)
	}
	return scp.Download(c.Raw(), remote, local)
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

func parseTarget(s string, defPort int) (user, host string, port int, err error) {
	port = defPort
	if at := strings.LastIndex(s, "@"); at >= 0 {
		user = s[:at]
		s = s[at+1:]
	}
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

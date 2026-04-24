// Package cliutil holds small pieces shared between the gossh-family
// CLI binaries: a repeatable string flag and the [user@]host[:port]
// parser. Keeping these in one place avoids drift between gossh and
// gossh-scp.
package cliutil

import (
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/oscar/gossh/internal/knownhosts"
)

// MultiFlag is a flag.Value that accumulates every -flag=VALUE
// invocation into a slice. Register with flag.Var.
type MultiFlag []string

func (m *MultiFlag) String() string     { return fmt.Sprintf("%v", []string(*m)) }
func (m *MultiFlag) Set(s string) error { *m = append(*m, s); return nil }

// FlagSet reports whether flag `name` was explicitly passed on the
// command line (as opposed to left at its default).
func FlagSet(name string) bool {
	seen := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			seen = true
		}
	})
	return seen
}

// ParseTarget splits a "[user@]host[:port]" or "[user@][ipv6]:port"
// argument into its components. The IPv6 case is recognised by a
// leading '[' on the host portion. portExplicit reports whether the
// target string itself specified a port — callers need this to decide
// precedence vs. ssh_config, because `alias:22` must beat a config
// `Port` even though the value coincides with the default.
func ParseTarget(s string, defPort int) (user, host string, port int, portExplicit bool, err error) {
	port = defPort
	if at := strings.LastIndex(s, "@"); at >= 0 {
		user = s[:at]
		s = s[at+1:]
	}
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", "", 0, false, fmt.Errorf("unterminated IPv6 bracket in %q", s)
		}
		host = s[1:end]
		rest := s[end+1:]
		if rest == "" {
			return user, host, port, false, nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", "", 0, false, fmt.Errorf("unexpected %q after IPv6", rest)
		}
		p, perr := strconv.Atoi(rest[1:])
		if perr != nil {
			return "", "", 0, false, fmt.Errorf("bad port %q", rest[1:])
		}
		return user, host, p, true, nil
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		host = s[:i]
		p, perr := strconv.Atoi(s[i+1:])
		if perr != nil {
			return "", "", 0, false, fmt.Errorf("bad port %q", s[i+1:])
		}
		return user, host, p, true, nil
	}
	return user, s, port, false, nil
}

// ParseStrictHostKey maps the `-strict-host-key` flag value to a
// knownhosts.Mode. Only two modes exist: strict (default) and
// accept-new (TOFU). An explicit "off" switch is intentionally not
// offered — disabling host-key verification is a MITM foot-gun.
func ParseStrictHostKey(v string) (knownhosts.Mode, error) {
	switch v {
	case "", "yes", "ask", "strict":
		return knownhosts.Strict, nil
	case "accept-new":
		return knownhosts.AcceptNew, nil
	default:
		return 0, fmt.Errorf("unknown strict-host-key %q (use yes or accept-new)", v)
	}
}

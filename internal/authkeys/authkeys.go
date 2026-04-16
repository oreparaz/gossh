// Package authkeys parses OpenSSH authorized_keys files.
//
// Only features we actually enforce are surfaced. Anything else in the
// options list is stored in Raw but has no effect; this keeps the
// threat model obvious.
package authkeys

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Entry is a single key line from an authorized_keys file.
type Entry struct {
	Key     ssh.PublicKey
	Comment string
	Options Options
}

// HostPort is a (host, port) pair. Host may be "*" or "0.0.0.0" or "localhost".
// Port may be 0 to match any.
type HostPort struct {
	Host string
	Port uint16 // 0 = any
}

// Options is the parsed, recognised subset of OpenSSH authorized_keys
// options. Unknown options are preserved in Raw but do not grant or
// restrict anything.
type Options struct {
	// Command, if non-empty, forces the session to run exactly this
	// command regardless of what the client asked for.
	Command string

	// From is the list of source patterns (hostnames, addresses, CIDR,
	// with optional leading "!" for negation) that may use this key.
	// An empty list means "any source".
	From []string

	// PermitOpen restricts where direct-tcpip (-L) tunnels may go.
	// Empty means "no direct-tcpip allowed unless no-port-forwarding
	// is explicitly negated by another option".
	PermitOpen []HostPort

	// PermitListen restricts which bind addresses a client may use
	// for remote forwarding (-R).
	PermitListen []HostPort

	// Environment sets variables in the child process.
	Environment map[string]string

	// Restrict is the OpenSSH "restrict" keyword. It disables all
	// permissions unless another option re-enables them.
	Restrict bool

	// Individual "no-*" toggles.
	NoPortForwarding  bool
	NoX11Forwarding   bool
	NoAgentForwarding bool
	NoPTY             bool
	NoUserRC          bool

	// Raw is the verbatim option string (before key type). Useful
	// for diagnostics.
	Raw string
}

// Parse reads an authorized_keys stream and returns its entries.
// Lines that are empty or start with # are ignored.
func Parse(r io.Reader) ([]Entry, error) {
	var out []Entry
	scanner := bufio.NewScanner(r)
	// Some legitimate authorized_keys lines (long RSA keys with many
	// permitopen= options) can easily exceed the default 64 KiB.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		key, comment, rawOpts, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		opts, err := parseOptions(rawOpts)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		out = append(out, Entry{
			Key:     key,
			Comment: comment,
			Options: opts,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ParseFile reads the file at path. It enforces the OpenSSH rule that
// the file must not be group- or world-writable.
func ParseFile(path string) ([]Entry, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if mode := info.Mode().Perm(); mode&0o022 != 0 {
		return nil, fmt.Errorf("authorized_keys %s is group/world writable (%#o)", path, mode)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// parseOptions turns the raw option slice ssh.ParseAuthorizedKey returned
// into a structured Options value.
func parseOptions(raw []string) (Options, error) {
	var opts Options
	opts.Raw = strings.Join(raw, ",")
	// Track options that were explicitly enabled so "restrict" does
	// not clobber them (e.g. `restrict,pty` keeps PTY allowed).
	enabled := map[string]bool{}
	for _, r := range raw {
		name, val, hasVal := splitOption(r)
		if hasVal {
			unq, err := unquote(val)
			if err != nil {
				return opts, fmt.Errorf("option %q: %w", name, err)
			}
			val = unq
		}
		nameL := strings.ToLower(name)
		switch nameL {
		case "restrict":
			opts.Restrict = true
		case "no-port-forwarding":
			opts.NoPortForwarding = true
		case "no-x11-forwarding":
			opts.NoX11Forwarding = true
		case "no-agent-forwarding":
			opts.NoAgentForwarding = true
		case "no-pty":
			opts.NoPTY = true
		case "no-user-rc":
			opts.NoUserRC = true
		case "port-forwarding":
			enabled["port-forwarding"] = true
			opts.NoPortForwarding = false
		case "x11-forwarding":
			enabled["x11-forwarding"] = true
			opts.NoX11Forwarding = false
		case "agent-forwarding":
			enabled["agent-forwarding"] = true
			opts.NoAgentForwarding = false
		case "pty":
			enabled["pty"] = true
			opts.NoPTY = false
		case "user-rc":
			enabled["user-rc"] = true
			opts.NoUserRC = false
		case "command":
			if !hasVal {
				return opts, fmt.Errorf(`command= requires a value`)
			}
			opts.Command = val
		case "from":
			if !hasVal {
				return opts, fmt.Errorf(`from= requires a value`)
			}
			opts.From = splitPatternList(val)
		case "permitopen":
			if !hasVal {
				return opts, fmt.Errorf(`permitopen= requires a value`)
			}
			hp, err := parseHostPort(val)
			if err != nil {
				return opts, err
			}
			opts.PermitOpen = append(opts.PermitOpen, hp)
		case "permitlisten":
			if !hasVal {
				return opts, fmt.Errorf(`permitlisten= requires a value`)
			}
			hp, err := parseHostPort(val)
			if err != nil {
				return opts, err
			}
			opts.PermitListen = append(opts.PermitListen, hp)
		case "environment":
			if !hasVal {
				return opts, fmt.Errorf(`environment= requires a value`)
			}
			eq := strings.IndexByte(val, '=')
			if eq <= 0 {
				return opts, fmt.Errorf(`environment=%q missing NAME=VALUE`, val)
			}
			if opts.Environment == nil {
				opts.Environment = make(map[string]string)
			}
			opts.Environment[val[:eq]] = val[eq+1:]
		}
		// Silently ignore unknown options; OpenSSH rejects them,
		// but we prefer to keep the config tolerant for non-enforced
		// keywords. Raw still has the original.
	}
	if opts.Restrict {
		if !enabled["port-forwarding"] {
			opts.NoPortForwarding = true
		}
		if !enabled["x11-forwarding"] {
			opts.NoX11Forwarding = true
		}
		if !enabled["agent-forwarding"] {
			opts.NoAgentForwarding = true
		}
		if !enabled["pty"] {
			opts.NoPTY = true
		}
		if !enabled["user-rc"] {
			opts.NoUserRC = true
		}
	}
	return opts, nil
}

// unquote strips the surrounding double quotes from an OpenSSH option
// value and un-escapes backslash-quoted characters. It accepts bare
// (unquoted) values too for forward compatibility with ssh-keygen's
// output.
func unquote(s string) (string, error) {
	if len(s) == 0 || s[0] != '"' {
		return s, nil
	}
	if len(s) < 2 || s[len(s)-1] != '"' {
		return "", fmt.Errorf("unterminated quoted value: %q", s)
	}
	inner := s[1 : len(s)-1]
	var out strings.Builder
	out.Grow(len(inner))
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c == '\\' && i+1 < len(inner) {
			i++
			out.WriteByte(inner[i])
			continue
		}
		out.WriteByte(c)
	}
	return out.String(), nil
}

func splitOption(s string) (name, value string, hasVal bool) {
	eq := strings.IndexByte(s, '=')
	if eq < 0 {
		return s, "", false
	}
	name = s[:eq]
	value = s[eq+1:]
	// ssh.ParseAuthorizedKey already unquoted; leave value as-is.
	return name, value, true
}

func splitPatternList(s string) []string {
	// OpenSSH pattern lists are comma-separated.
	raw := strings.Split(s, ",")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseHostPort(s string) (HostPort, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return HostPort{}, fmt.Errorf("permitopen/permitlisten %q: %w", s, err)
	}
	if portStr == "*" {
		return HostPort{Host: host, Port: 0}, nil
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return HostPort{}, fmt.Errorf("permitopen/permitlisten port %q: %w", portStr, err)
	}
	return HostPort{Host: host, Port: port}, nil
}

// ErrKeyNotFound is returned by Find when no matching entry exists.
var ErrKeyNotFound = errors.New("public key not authorized")

// Find returns the first entry whose key matches the given public key,
// or ErrKeyNotFound.
func Find(entries []Entry, key ssh.PublicKey) (*Entry, error) {
	wanted := key.Marshal()
	for i := range entries {
		if bytes.Equal(entries[i].Key.Marshal(), wanted) {
			return &entries[i], nil
		}
	}
	return nil, ErrKeyNotFound
}

// Package sshconfig parses a small, safe subset of ssh_config /
// sshd_config. The goal is drop-in compatibility for the directives
// we actually act on; unknown keywords are ignored (with a warning
// optionally captured through the Errors slice).
//
// Out of scope: Include directives, pattern match wildcards beyond
// "*" catch-all, Match blocks, token expansion (%h, %p, etc.).
package sshconfig

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// ClientHost is a resolved host-specific client config.
type ClientHost struct {
	Host          string
	Hostname      string
	Port          int
	User          string
	IdentityFiles []string
	StrictHost    string // "yes" / "accept-new" / "no"
	KnownHosts    string
	ProxyCommand  string // verbatim, with unexpanded %h/%p/%r tokens
}

// ClientConfig is the parsed ssh_config: a list of Host sections,
// applied in order. Earliest match wins (that is OpenSSH semantics).
type ClientConfig struct {
	Sections []clientSection
}

type clientSection struct {
	Patterns []string
	Opts     map[string]string
}

// ResolveHost walks the sections in order and builds a ClientHost
// for the requested alias. Values from the first matching section
// win; later sections can still *add* new keys, but not overwrite.
// (OpenSSH applies directives first-wins per keyword.)
func (c *ClientConfig) ResolveHost(host string) ClientHost {
	merged := map[string]string{}
	var identities []string
	for _, sec := range c.Sections {
		if !matchAny(sec.Patterns, host) {
			continue
		}
		for k, v := range sec.Opts {
			if _, ok := merged[k]; !ok {
				merged[k] = v
			}
		}
		// IdentityFile is additive.
		if v, ok := sec.Opts["identityfile"]; ok {
			for _, p := range strings.Fields(v) {
				identities = append(identities, expandUser(p))
			}
		}
	}
	out := ClientHost{Host: host}
	if v := merged["hostname"]; v != "" {
		out.Hostname = v
	} else {
		out.Hostname = host
	}
	if v := merged["port"]; v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			out.Port = p
		}
	}
	out.User = merged["user"]
	out.IdentityFiles = identities
	out.StrictHost = merged["stricthostkeychecking"]
	out.KnownHosts = expandUser(merged["userknownhostsfile"])
	out.ProxyCommand = merged["proxycommand"]
	return out
}

func matchAny(patterns []string, host string) bool {
	for _, p := range patterns {
		if p == "*" || strings.EqualFold(p, host) {
			return true
		}
	}
	return false
}

// ParseClient parses an ssh_config stream.
func ParseClient(r io.Reader) (*ClientConfig, error) {
	c := &ClientConfig{}
	current := clientSection{Patterns: []string{"*"}, Opts: map[string]string{}}
	scanner := bufio.NewScanner(r)
	lineNo := 0
	flushCurrent := func() {
		if len(current.Opts) > 0 {
			c.Sections = append(c.Sections, current)
		}
	}
	for scanner.Scan() {
		lineNo++
		line := stripComment(scanner.Text())
		if line == "" {
			continue
		}
		key, val, err := parseKV(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		lk := strings.ToLower(key)
		if lk == "host" {
			flushCurrent()
			current = clientSection{Patterns: strings.Fields(val), Opts: map[string]string{}}
			continue
		}
		if lk == "match" || lk == "include" {
			// Silently skipped — see package doc for the scope cut.
			continue
		}
		if lk == "identityfile" {
			// IdentityFile is accumulative: multiple lines contribute
			// a list of candidate keys, not "last one wins".
			if prev := current.Opts[lk]; prev != "" {
				current.Opts[lk] = prev + " " + val
			} else {
				current.Opts[lk] = val
			}
			continue
		}
		current.Opts[lk] = val
	}
	flushCurrent()
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return c, nil
}

// ParseClientFile is a convenience wrapper around ParseClient.
func ParseClientFile(path string) (*ClientConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseClient(f)
}

// ServerConfig is the parsed sshd_config. Only the fields the server
// actually consumes are kept — silently-stored-but-ignored fields
// mislead operators who write them expecting enforcement.
type ServerConfig struct {
	Port                   int
	HostKeys               []string
	AuthorizedKeysFile     string
	PermitRootLogin        string // "no" / "prohibit-password" / "yes"
	PasswordAuthentication bool   // rejected at startup if true
	MaxAuthTries           int
}

// ParseServer parses an sshd_config stream. Unknown keywords are
// silently ignored — sshd_config has a large vocabulary and we want
// drop-in files to work.
func ParseServer(r io.Reader) (*ServerConfig, error) {
	s := &ServerConfig{
		PermitRootLogin:        "prohibit-password",
		PasswordAuthentication: false,
	}
	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := stripComment(scanner.Text())
		if line == "" {
			continue
		}
		key, val, err := parseKV(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		switch strings.ToLower(key) {
		case "port":
			p, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: bad Port %q", lineNo, val)
			}
			s.Port = p
		case "hostkey":
			s.HostKeys = append(s.HostKeys, expandUser(val))
		case "authorizedkeysfile":
			s.AuthorizedKeysFile = expandUser(val)
		case "permitrootlogin":
			s.PermitRootLogin = val
		case "passwordauthentication":
			s.PasswordAuthentication = truthy(val)
		case "maxauthtries":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: bad MaxAuthTries %q", lineNo, val)
			}
			s.MaxAuthTries = n
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return s, nil
}

func ParseServerFile(path string) (*ServerConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseServer(f)
}

// stripComment removes a line's trailing comment. It drops the
// portion from the first unquoted '#' to the end of the line, so
// both OpenSSH full-line comments and the looser inline form like
//
//	Port 2222 # my ssh port
//	IdentityFile "~/my key" # with a #hash in it
//
// parse the way an operator expects. Hashes inside a double-quoted
// value are preserved. Backslash-escapes inside the quoted value
// are honoured minimally (just `\"`).
func stripComment(s string) string {
	// Fast path: trim whitespace, handle whole-line comments.
	t := strings.TrimSpace(s)
	if t == "" || strings.HasPrefix(t, "#") {
		return ""
	}
	inQuote := false
	escape := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escape {
			escape = false
			continue
		}
		if c == '\\' && inQuote {
			escape = true
			continue
		}
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if c == '#' && !inQuote {
			return strings.TrimSpace(s[:i])
		}
	}
	return strings.TrimSpace(s)
}

func parseKV(s string) (string, string, error) {
	// The keyword is the first whitespace- or '='-delimited token.
	// After it, '=' (optionally surrounded by whitespace) separates
	// key from value; otherwise whitespace does. Crucially, a '='
	// INSIDE the value (e.g. "ProxyCommand ... portNumber=%p") must
	// not be treated as the separator.
	i := 0
	for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != '=' {
		i++
	}
	if i == 0 {
		return "", "", fmt.Errorf("no key in %q", s)
	}
	key := s[:i]
	rest := strings.TrimLeft(s[i:], " \t")
	if strings.HasPrefix(rest, "=") {
		rest = strings.TrimLeft(rest[1:], " \t")
	}
	if rest == "" {
		return "", "", fmt.Errorf("no value for key %q", key)
	}
	return key, rest, nil
}

func truthy(s string) bool {
	switch strings.ToLower(s) {
	case "yes", "true", "on", "1":
		return true
	}
	return false
}

func expandUser(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + p[1:]
		}
	}
	return p
}

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
}

// ClientConfig is the parsed ssh_config: a list of Host sections,
// applied in order. Earliest match wins (that is OpenSSH semantics).
type ClientConfig struct {
	Sections []clientSection
	Warnings []string
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
			c.Warnings = append(c.Warnings, fmt.Sprintf("line %d: %q directive ignored", lineNo, key))
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

// ServerConfig is the parsed sshd_config.
type ServerConfig struct {
	Port                   int
	ListenAddresses        []string
	HostKeys               []string
	AuthorizedKeysFile     string
	PermitRootLogin        string // "no" / "prohibit-password" / "yes"
	PasswordAuthentication bool
	AllowTCPForwarding     string // "yes" / "no" / "local" / "remote"
	LoginGraceTime         string
	MaxAuthTries           int
	Warnings               []string
}

// ParseServer parses an sshd_config stream. Unknown keywords are
// silently ignored; they become Warnings only when enabled in the
// top-level API (this is what sshd_config does when a CLI flag
// overrides a file value — the file is best-effort).
func ParseServer(r io.Reader) (*ServerConfig, error) {
	s := &ServerConfig{
		PermitRootLogin:        "prohibit-password",
		PasswordAuthentication: false,
		AllowTCPForwarding:     "yes",
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
		case "listenaddress":
			s.ListenAddresses = append(s.ListenAddresses, val)
		case "hostkey":
			s.HostKeys = append(s.HostKeys, expandUser(val))
		case "authorizedkeysfile":
			s.AuthorizedKeysFile = expandUser(val)
		case "permitrootlogin":
			s.PermitRootLogin = val
		case "passwordauthentication":
			s.PasswordAuthentication = truthy(val)
		case "allowtcpforwarding":
			s.AllowTCPForwarding = val
		case "logingracetime":
			s.LoginGraceTime = val
		case "maxauthtries":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: bad MaxAuthTries %q", lineNo, val)
			}
			s.MaxAuthTries = n
		default:
			s.Warnings = append(s.Warnings, fmt.Sprintf("line %d: ignoring %q", lineNo, key))
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

func stripComment(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "#") {
		return ""
	}
	return s
}

func parseKV(s string) (string, string, error) {
	// Accept "key value", "key=value", and "key\tvalue".
	if eq := strings.IndexByte(s, '='); eq > 0 {
		return strings.TrimSpace(s[:eq]), strings.TrimSpace(s[eq+1:]), nil
	}
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return "", "", fmt.Errorf("no value for key %q", s)
	}
	return fields[0], strings.TrimSpace(s[len(fields[0]):]), nil
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

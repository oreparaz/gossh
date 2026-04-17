package authkeys

import (
	"net"
	"strings"
)

// MatchFrom reports whether a remote address satisfies an OpenSSH
// from="pattern-list" restriction.
//
// Patterns are comma-separated. Each pattern may be:
//
//   - an IP literal or CIDR prefix (e.g. "10.0.0.0/8", "::1")
//   - a hostname possibly containing "*" / "?" wildcards
//   - any of the above with a leading "!" to negate
//
// Semantics (matching OpenSSH):
//
//  1. If any negated pattern matches, deny.
//  2. Else if any positive pattern matches, allow.
//  3. Else deny.
//
// A nil/empty patterns slice is treated as "no restriction, allow".
// remoteIP may be nil — hostname matching falls back to skipping
// patterns that need an IP.
func MatchFrom(patterns []string, remoteIP net.IP, remoteHost string) bool {
	if len(patterns) == 0 {
		return true
	}
	// Pass 1: if any negation matches, deny outright.
	// Pass 2: require a positive match (unless there were only
	// negations, in which case any non-denied address is allowed).
	anyPositive := false
	matchedPositive := false
	for _, p := range patterns {
		if strings.HasPrefix(p, "!") {
			if matchOne(p[1:], remoteIP, remoteHost) {
				return false
			}
			continue
		}
		anyPositive = true
		if matchOne(p, remoteIP, remoteHost) {
			matchedPositive = true
		}
	}
	if !anyPositive {
		return true // only negations, none matched
	}
	return matchedPositive
}

func matchOne(pattern string, ip net.IP, host string) bool {
	// CIDR?
	if strings.Contains(pattern, "/") {
		if _, cidr, err := net.ParseCIDR(pattern); err == nil {
			return ip != nil && cidr.Contains(ip)
		}
	}
	// Bare IP literal?
	if pip := net.ParseIP(pattern); pip != nil {
		return ip != nil && pip.Equal(ip)
	}
	// Hostname with wildcards.
	return wildcardMatch(strings.ToLower(pattern), strings.ToLower(host))
}

// wildcardMatch implements the OpenSSH-style glob: '*' matches any
// sequence, '?' matches one character. Everything else is literal
// and case-insensitive (caller lowercases).
func wildcardMatch(pattern, name string) bool {
	// Iterative match with backtracking on '*'.
	p, n := 0, 0
	starP, starN := -1, -1
	for n < len(name) {
		if p < len(pattern) && (pattern[p] == '?' || pattern[p] == name[n]) {
			p++
			n++
			continue
		}
		if p < len(pattern) && pattern[p] == '*' {
			starP = p
			starN = n
			p++
			continue
		}
		if starP >= 0 {
			p = starP + 1
			starN++
			n = starN
			continue
		}
		return false
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

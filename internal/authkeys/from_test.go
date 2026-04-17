package authkeys

import (
	"net"
	"testing"
)

func TestMatchFromEmptyAllows(t *testing.T) {
	if !MatchFrom(nil, net.ParseIP("1.2.3.4"), "anything") {
		t.Fatal("empty pattern list should allow everything")
	}
}

func TestMatchFromIPv4Literal(t *testing.T) {
	if !MatchFrom([]string{"10.0.0.1"}, net.ParseIP("10.0.0.1"), "") {
		t.Fatal("exact IP must match")
	}
	if MatchFrom([]string{"10.0.0.1"}, net.ParseIP("10.0.0.2"), "") {
		t.Fatal("different IP must not match")
	}
}

func TestMatchFromCIDR(t *testing.T) {
	if !MatchFrom([]string{"10.0.0.0/8"}, net.ParseIP("10.2.3.4"), "") {
		t.Fatal("CIDR should include in-range addr")
	}
	if MatchFrom([]string{"10.0.0.0/8"}, net.ParseIP("192.0.0.1"), "") {
		t.Fatal("CIDR should exclude out-of-range addr")
	}
}

func TestMatchFromIPv6(t *testing.T) {
	if !MatchFrom([]string{"::1"}, net.ParseIP("::1"), "") {
		t.Fatal("IPv6 literal")
	}
	if !MatchFrom([]string{"fe80::/10"}, net.ParseIP("fe80::dead"), "") {
		t.Fatal("IPv6 CIDR")
	}
}

func TestMatchFromHostWildcard(t *testing.T) {
	if !MatchFrom([]string{"*.example.com"}, nil, "foo.example.com") {
		t.Fatal("wildcard should match subdomain")
	}
	if MatchFrom([]string{"*.example.com"}, nil, "example.com") {
		t.Fatal("*.example.com should NOT match bare example.com")
	}
	if !MatchFrom([]string{"host?.example.com"}, nil, "host1.example.com") {
		t.Fatal("? wildcard")
	}
}

func TestMatchFromNegation(t *testing.T) {
	// Positive range minus a hole.
	patterns := []string{"10.0.0.0/8", "!10.0.0.13"}
	if !MatchFrom(patterns, net.ParseIP("10.2.3.4"), "") {
		t.Fatal("positive case should match")
	}
	if MatchFrom(patterns, net.ParseIP("10.0.0.13"), "") {
		t.Fatal("negation should exclude")
	}
	if MatchFrom(patterns, net.ParseIP("192.0.0.1"), "") {
		t.Fatal("outside range should fall through to deny")
	}
}

func TestMatchFromOnlyNegations(t *testing.T) {
	// `!10.0.0.13` alone means "everything except that IP".
	patterns := []string{"!10.0.0.13"}
	if !MatchFrom(patterns, net.ParseIP("1.2.3.4"), "") {
		t.Fatal("non-matching addr should be allowed")
	}
	if MatchFrom(patterns, net.ParseIP("10.0.0.13"), "") {
		t.Fatal("negated addr should be denied")
	}
}

func TestMatchFromCaseInsensitive(t *testing.T) {
	if !MatchFrom([]string{"HOST.example.com"}, nil, "host.example.com") {
		t.Fatal("hostname match is case-insensitive")
	}
}

func TestMatchFromStarMatchesAll(t *testing.T) {
	if !MatchFrom([]string{"*"}, net.ParseIP("1.2.3.4"), "anything") {
		t.Fatal("* should match any host")
	}
}

func TestMatchFromDenyThenAllow(t *testing.T) {
	// Regardless of order, the negation must win when its pattern matches.
	patterns := []string{"!1.2.3.4", "*"}
	if MatchFrom(patterns, net.ParseIP("1.2.3.4"), "") {
		t.Fatal("negated IP must be denied even when * would allow")
	}
	if !MatchFrom(patterns, net.ParseIP("10.0.0.1"), "") {
		t.Fatal("* should cover other IPs")
	}
}

func TestMatchFromMalformedCIDRIsIgnored(t *testing.T) {
	// A malformed CIDR pattern should not match anything; it must
	// also not panic.
	if MatchFrom([]string{"notacidr/99"}, net.ParseIP("1.2.3.4"), "") {
		t.Fatal("malformed pattern should not match")
	}
}

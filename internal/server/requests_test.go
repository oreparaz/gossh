package server

import "testing"

func TestIsSafeEnvName(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		// Allowlisted.
		{"TERM", true},
		{"LANG", true},
		{"LC_ALL", true},
		{"LC_CTYPE", true},
		{"LC_ANYTHING", true},
		{"SSH_ORIGINAL_COMMAND", true},

		// Not on allowlist (even though charset is fine).
		{"PATH", false},
		{"HOME", false},
		{"LD_PRELOAD", false},
		{"USER", false},
		{"FOO", false},

		// Bad charset — never even considered.
		{"", false},
		{"1ABC", false},      // leading digit
		{"lowercase", false}, // lowercase not allowed
		{"LC=1", false},      // '=' in name
		{"LC ALL", false},    // space
		{"LC.BAR", false},    // dot
		{"LC-BAR", false},    // dash
	}
	for _, tc := range cases {
		if got := isSafeEnvName(tc.name); got != tc.ok {
			t.Errorf("isSafeEnvName(%q) = %v, want %v", tc.name, got, tc.ok)
		}
	}
}

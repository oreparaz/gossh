package cliutil

import "testing"

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in           string
		defPort      int
		wantUser     string
		wantHost     string
		wantPort     int
		wantExplicit bool
		wantErr      bool
	}{
		{"host", 22, "", "host", 22, false, false},
		{"user@host", 22, "user", "host", 22, false, false},
		{"user@host:2222", 22, "user", "host", 2222, true, false},
		{"host:2222", 22, "", "host", 2222, true, false},
		// Explicit port that happens to equal the default must still
		// report portExplicit=true — otherwise ssh_config can silently
		// override the user's intent.
		{"host:22", 22, "", "host", 22, true, false},
		{"[::1]", 22, "", "::1", 22, false, false},
		{"[::1]:2222", 22, "", "::1", 2222, true, false},
		{"user@[::1]:2222", 22, "user", "::1", 2222, true, false},
		{"host:notaport", 22, "", "", 0, false, true},
		{"[::1", 22, "", "", 0, false, true},
	}
	for _, c := range cases {
		gotUser, gotHost, gotPort, gotExplicit, err := ParseTarget(c.in, c.defPort)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseTarget(%q): err=%v wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if gotUser != c.wantUser || gotHost != c.wantHost || gotPort != c.wantPort || gotExplicit != c.wantExplicit {
			t.Errorf("ParseTarget(%q) = %q,%q,%d,explicit=%v; want %q,%q,%d,explicit=%v",
				c.in, gotUser, gotHost, gotPort, gotExplicit,
				c.wantUser, c.wantHost, c.wantPort, c.wantExplicit)
		}
	}
}

func TestParseStrictHostKey(t *testing.T) {
	strict := []string{"", "yes", "ask", "strict"}
	for _, v := range strict {
		if _, err := ParseStrictHostKey(v); err != nil {
			t.Errorf("ParseStrictHostKey(%q): %v", v, err)
		}
	}
	if _, err := ParseStrictHostKey("accept-new"); err != nil {
		t.Errorf("accept-new: %v", err)
	}
	for _, v := range []string{"no", "off", "garbage"} {
		if _, err := ParseStrictHostKey(v); err == nil {
			t.Errorf("ParseStrictHostKey(%q) should have failed", v)
		}
	}
}

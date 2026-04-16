package forward

import "testing"

func TestParseLocal(t *testing.T) {
	cases := []struct {
		in   string
		want Spec
	}{
		{"8080:example.com:80", Spec{BindAddr: "", BindPort: 8080, TargetHost: "example.com", TargetPort: 80}},
		{"127.0.0.1:8080:example.com:80", Spec{BindAddr: "127.0.0.1", BindPort: 8080, TargetHost: "example.com", TargetPort: 80}},
		{"0:localhost:22", Spec{BindAddr: "", BindPort: 0, TargetHost: "localhost", TargetPort: 22}},
		{"[::1]:8080:[::2]:80", Spec{BindAddr: "::1", BindPort: 8080, TargetHost: "::2", TargetPort: 80}},
	}
	for _, c := range cases {
		got, err := ParseLocal(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q: got %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestParseLocalErrors(t *testing.T) {
	for _, in := range []string{"", "8080", "bad:port", "[::1:8080"} {
		if _, err := ParseLocal(in); err == nil {
			t.Errorf("%q: expected error", in)
		}
	}
}

func TestParseDynamic(t *testing.T) {
	s, err := ParseDynamic("1080")
	if err != nil || s.BindPort != 1080 {
		t.Fatalf("got %+v err %v", s, err)
	}
	s, err = ParseDynamic("127.0.0.1:1080")
	if err != nil || s.BindAddr != "127.0.0.1" || s.BindPort != 1080 {
		t.Fatalf("got %+v err %v", s, err)
	}
}

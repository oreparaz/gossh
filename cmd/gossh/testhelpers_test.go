package main_test

import (
	"path/filepath"
	"runtime"
)

// goBinary returns the path to the `go` executable from the toolchain
// that built the running test binary. Test files use this instead of
// hard-coding /usr/local/go/bin/go so the tests work both on dev
// machines and on CI runners (where setup-go installs to
// /opt/hostedtoolcache/go/<ver>/x64/bin/go).
func goBinary() string {
	return filepath.Join(runtime.GOROOT(), "bin", "go")
}

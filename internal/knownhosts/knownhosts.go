// Package knownhosts is a thin TOFU wrapper around
// golang.org/x/crypto/ssh/knownhosts.
//
// The wrapped stdlib package handles the file format — hashed host
// entries, CA/revoked markers, port notation, wildcards — so our job
// is just to layer on the two things it deliberately leaves to the
// caller: (1) what to do when a host is unknown (strict reject vs.
// trust-on-first-use append) and (2) atomic, locked writes to the
// known_hosts file.
package knownhosts

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	xkh "golang.org/x/crypto/ssh/knownhosts"
)

// Mode controls how unknown hosts are handled.
type Mode int

const (
	// Strict refuses connections whose host key is not already
	// recorded. This is the only safe default for production.
	Strict Mode = iota

	// TOFU accepts the first host key presented and records it. On
	// subsequent connects it behaves like Strict.
	TOFU

	// AcceptNew is a synonym for TOFU; it matches OpenSSH's
	// StrictHostKeyChecking=accept-new.
	AcceptNew

	// Off skips host-key verification entirely. It is never the right
	// setting outside of scratch tests. Opting into it requires passing
	// this enum explicitly.
	Off
)

// Verifier is reused for the lifetime of a client; it is safe for
// concurrent use (appends are serialised).
type Verifier struct {
	path string
	mode Mode

	mu  sync.Mutex // guards appends and in-memory callback rebuilds
	cbk ssh.HostKeyCallback
}

// New returns a Verifier backed by the given known_hosts file path.
// The file does not need to exist; it will be created on first append.
// Parent directories are created with 0700.
func New(path string, mode Mode) (*Verifier, error) {
	if path == "" && mode != Off {
		return nil, errors.New("known_hosts path required unless mode is Off")
	}
	v := &Verifier{path: path, mode: mode}
	if err := v.reload(); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *Verifier) reload() error {
	if v.mode == Off {
		v.cbk = ssh.InsecureIgnoreHostKey() //nolint:gosec
		return nil
	}
	// Ensure the file exists so xkh.New does not error on a missing path.
	if _, err := os.Stat(v.path); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(v.path), 0o700); err != nil {
			return err
		}
		f, err := os.OpenFile(v.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		if f != nil {
			_ = f.Close()
		}
	} else if err != nil {
		return err
	}
	cbk, err := xkh.New(v.path)
	if err != nil {
		return fmt.Errorf("load known_hosts: %w", err)
	}
	v.cbk = cbk
	return nil
}

// HostKeyCallback returns an ssh.HostKeyCallback suitable for
// ssh.ClientConfig.
func (v *Verifier) HostKeyCallback() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		v.mu.Lock()
		cbk := v.cbk
		mode := v.mode
		v.mu.Unlock()
		err := cbk(hostname, remote, key)
		if err == nil {
			return nil
		}
		var kerr *xkh.KeyError
		if !errors.As(err, &kerr) {
			return err
		}
		// Host exists but key mismatch → always reject (possible MITM).
		if len(kerr.Want) > 0 {
			return fmt.Errorf("host key mismatch for %s: %w", hostname, err)
		}
		// Host unknown.
		switch mode {
		case Strict:
			return fmt.Errorf("host key for %s not in known_hosts (strict mode): %w", hostname, err)
		case TOFU, AcceptNew:
			if appendErr := v.Append(hostname, remote, key); appendErr != nil {
				return fmt.Errorf("TOFU append: %w", appendErr)
			}
			return nil
		case Off:
			return nil
		}
		return err
	}
}

// Append writes a new host/key line to known_hosts and refreshes the
// in-memory database so subsequent callbacks see it.
func (v *Verifier) Append(hostname string, remote net.Addr, key ssh.PublicKey) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	addrs := canonicalAddresses(hostname, remote)
	line := xkh.Line(addrs, key) + "\n"
	f, err := os.OpenFile(v.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(line); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Rebuild in-memory callback from disk. The stdlib package has no
	// incremental add, so we reload; known_hosts files are small.
	return v.reload()
}

// canonicalAddresses returns the list of addresses we want to record
// for this host. It includes "hostname" (possibly with port if it is
// non-default) and the remote network address, deduped.
func canonicalAddresses(hostname string, remote net.Addr) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s == "" {
			return
		}
		n := xkh.Normalize(s)
		if seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	add(hostname)
	if remote != nil {
		add(remote.String())
	}
	// Strip any bracketed form down to host alone when the port is 22.
	// This keeps the file compact.
	if len(out) > 1 {
		// nothing to do — ssh/knownhosts.Line handles bracketing.
		_ = strings.Join
	}
	return out
}

// IsHostKeyChanged reports whether err indicates an on-disk key
// mismatch (possible MITM).
func IsHostKeyChanged(err error) bool {
	var kerr *xkh.KeyError
	return errors.As(err, &kerr) && len(kerr.Want) > 0
}

// IsHostUnknown reports whether err indicates the host was not present
// in the known_hosts file.
func IsHostUnknown(err error) bool {
	var kerr *xkh.KeyError
	return errors.As(err, &kerr) && len(kerr.Want) == 0
}

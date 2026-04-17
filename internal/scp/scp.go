// Package scp implements the legacy OpenSSH SCP wire protocol as a
// client. The protocol is a thin framing over stdin/stdout of a
// remote `scp -t` (sink, for upload) or `scp -f` (source, for
// download) process spawned via an SSH exec request.
//
// We implement single-file transfers only (no recursion, no
// directories). That covers the 90% use case and keeps the
// attack-surface tiny — SCP's known CVEs come almost exclusively
// from recursive-mode path handling.
package scp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Upload copies the local file at srcPath to the remote path dst via
// the SSH session. The remote side must run `scp -t <parent>` — in
// practice, we exec it ourselves below.
func Upload(client *ssh.Client, srcPath, dstPath string) error {
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("scp upload: %s is not a regular file", srcPath)
	}

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return err
	}

	// The remote scp -t expects a parent directory as arg and learns
	// the filename from our C-line. If dst ends with a slash or is
	// a directory-only path, use it verbatim; otherwise split.
	remoteDir, remoteName := splitRemote(dstPath)
	if remoteName == "" {
		remoteName = filepath.Base(srcPath)
	}
	if err := session.Start(fmt.Sprintf("scp -qt %s", shellQuote(remoteDir))); err != nil {
		return err
	}

	r := bufio.NewReader(stdout)
	if err := readAck(r, stderr); err != nil {
		return fmt.Errorf("initial ack: %w", err)
	}
	// Send C-line: C<mode> <size> <name>\n
	mode := info.Mode().Perm()
	header := fmt.Sprintf("C%04o %d %s\n", mode, info.Size(), remoteName)
	if _, err := io.WriteString(stdin, header); err != nil {
		return err
	}
	if err := readAck(r, stderr); err != nil {
		return fmt.Errorf("header ack: %w", err)
	}
	// Stream content.
	if _, err := io.Copy(stdin, f); err != nil {
		return err
	}
	// Trailing zero-byte (end-of-file marker per SCP).
	if _, err := stdin.Write([]byte{0}); err != nil {
		return err
	}
	if err := readAck(r, stderr); err != nil {
		return fmt.Errorf("content ack: %w", err)
	}
	// Close stdin → remote scp -t sees EOF, exits.
	_ = stdin.Close()
	return session.Wait()
}

// Download copies the remote file at srcPath to dstPath on the
// local host.
func Download(client *ssh.Client, srcPath, dstPath string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return err
	}

	if err := session.Start(fmt.Sprintf("scp -qf %s", shellQuote(srcPath))); err != nil {
		return err
	}

	r := bufio.NewReader(stdout)
	// Signal ready.
	if _, err := stdin.Write([]byte{0}); err != nil {
		return err
	}
	line, err := r.ReadString('\n')
	if err != nil {
		// Drain stderr for a more useful error.
		errMsg, _ := io.ReadAll(stderr)
		return fmt.Errorf("read header: %w: %s", err, strings.TrimSpace(string(errMsg)))
	}
	line = strings.TrimRight(line, "\n")
	if len(line) == 0 || line[0] != 'C' {
		errMsg, _ := io.ReadAll(stderr)
		return fmt.Errorf("expected C-line, got %q: %s", line, strings.TrimSpace(string(errMsg)))
	}
	mode, size, _, err := parseCLine(line)
	if err != nil {
		return err
	}
	// Ack the C-line.
	if _, err := stdin.Write([]byte{0}); err != nil {
		return err
	}

	// If dstPath is a directory, write into it using the remote name.
	localTarget := dstPath
	if fi, err := os.Stat(dstPath); err == nil && fi.IsDir() {
		_, rn, _ := parseCLineName(line)
		if rn == "" {
			rn = filepath.Base(srcPath)
		}
		localTarget = filepath.Join(dstPath, rn)
	}
	out, err := os.OpenFile(localTarget, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.CopyN(out, r, size); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	// Read the trailing 0 byte.
	trailing, err := r.ReadByte()
	if err != nil {
		return err
	}
	if trailing != 0 {
		return fmt.Errorf("expected trailing 0, got %#x", trailing)
	}
	// Ack completion.
	if _, err := stdin.Write([]byte{0}); err != nil {
		return err
	}
	_ = stdin.Close()
	return session.Wait()
}

// readAck consumes one SCP ack byte. Status 0 is success; 1 or 2 are
// warning/error and the remote writes a message line after.
func readAck(r *bufio.Reader, stderr io.Reader) error {
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	switch b {
	case 0:
		return nil
	case 1, 2:
		msg, _ := r.ReadString('\n')
		msg = strings.TrimRight(msg, "\n")
		errMsg, _ := io.ReadAll(stderr)
		if errMsg != nil && len(errMsg) > 0 {
			return fmt.Errorf("scp: %s (stderr: %s)", strings.TrimSpace(msg), strings.TrimSpace(string(errMsg)))
		}
		return fmt.Errorf("scp: %s", strings.TrimSpace(msg))
	default:
		return fmt.Errorf("unexpected ack byte %#x", b)
	}
}

// parseCLine parses "C<mode> <size> <name>" and returns (mode, size, name).
func parseCLine(line string) (os.FileMode, int64, string, error) {
	if len(line) == 0 || line[0] != 'C' {
		return 0, 0, "", fmt.Errorf("expected C-line, got %q", line)
	}
	body := line[1:]
	parts := strings.SplitN(body, " ", 3)
	if len(parts) != 3 {
		return 0, 0, "", fmt.Errorf("malformed C-line: %q", line)
	}
	mode, err := strconv.ParseUint(parts[0], 8, 32)
	if err != nil {
		return 0, 0, "", fmt.Errorf("bad mode %q: %w", parts[0], err)
	}
	// Enforce a safe mode range (no setuid / sticky surprises).
	if mode&0o7000 != 0 {
		return 0, 0, "", fmt.Errorf("refusing setuid/setgid/sticky mode in C-line: %#o", mode)
	}
	size, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || size < 0 {
		return 0, 0, "", fmt.Errorf("bad size %q", parts[1])
	}
	name := parts[2]
	if err := validateSCPFilename(name); err != nil {
		return 0, 0, "", err
	}
	return os.FileMode(mode), size, name, nil
}

// validateSCPFilename enforces that a C-line filename sent by the
// remote cannot escape the local destination directory. This is the
// cross-platform generalisation of the CVE-2019-6111 guard:
//
//   - POSIX separator "/" is always rejected (catches most attacks).
//   - NUL is rejected.
//   - Windows-specific characters "\", leading drive letters
//     (e.g. "C:evil"), and UNC prefixes ("\\host\share") are also
//     rejected so a Windows client using this package is safe even
//     though filepath.Join on Windows would happily interpret them.
//   - The bare names "." and ".." are rejected.
//   - Empty or excessively long names are rejected.
var errUnsafeName = errors.New("scp: unsafe filename in C-line")

func validateSCPFilename(name string) error {
	if name == "" || len(name) > 255 {
		return fmt.Errorf("%w: length", errUnsafeName)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("%w: %q", errUnsafeName, name)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '/' || c == '\\' || c == 0 {
			return fmt.Errorf("%w: contains separator or NUL", errUnsafeName)
		}
	}
	// Windows drive-letter prefix "X:..." where the rest would be a
	// drive-relative path. Even a bare "C:" is dangerous.
	if len(name) >= 2 && name[1] == ':' {
		c := name[0]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			return fmt.Errorf("%w: drive-letter prefix", errUnsafeName)
		}
	}
	return nil
}

// parseCLineName is a convenience that returns just the name; errors
// are silenced (parseCLine is the authoritative checker).
func parseCLineName(line string) (os.FileMode, string, error) {
	m, _, n, err := parseCLine(line)
	return m, n, err
}

// splitRemote separates dst into (parent-dir, filename). A bare path
// returns (.", path) for root-level writes.
func splitRemote(dst string) (dir, name string) {
	dst = strings.TrimRight(dst, "/")
	if dst == "" {
		return ".", ""
	}
	if !strings.Contains(dst, "/") {
		return ".", dst
	}
	idx := strings.LastIndexByte(dst, '/')
	return dst[:idx+1], dst[idx+1:]
}

// shellQuote single-quotes a path for safe use in a remote shell
// command. Embedded single quotes are escaped with the shell's
// standard '"'"' trick.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// ErrRefused is returned when the remote side actively refuses the
// transfer (e.g., permission denied, file not found).
var ErrRefused = errors.New("scp: refused by remote")

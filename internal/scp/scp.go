// Package scp implements the legacy OpenSSH SCP wire protocol as a
// client. The protocol is a thin framing over stdin/stdout of a
// remote `scp -t` (sink, for upload) or `scp -f` (source, for
// download) process spawned via an SSH exec request.
//
// Both single-file and recursive transfers are supported. Recursion
// has historically been the source of most SCP CVEs (filename
// injection escaping the destination directory), so every directory
// and file name received from the remote goes through
// validateSCPFilename; depth is capped at MaxRecursionDepth;
// symlinks on the local side are skipped on upload.
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

// MaxRecursionDepth bounds how deep a recursive transfer will go.
// A malicious remote can't walk us past this; a friendly remote
// that legitimately has deeper trees can bump it if needed.
const MaxRecursionDepth = 64

// Upload copies the local path to the remote dst via SSH. If srcPath
// is a directory, recursive must be true — otherwise the call errors
// loudly instead of silently skipping the tree.
func Upload(client *ssh.Client, srcPath, dstPath string, recursive bool) error {
	info, err := os.Lstat(srcPath)
	if err != nil {
		return err
	}
	if info.IsDir() && !recursive {
		return fmt.Errorf("scp upload: %s is a directory (use -r)", srcPath)
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

	// For a directory upload dstPath is the receiving parent and the
	// top-level D-line carries basename(srcPath) — matching OpenSSH
	// scp -r semantics (contents go into dstPath/basename(src)/).
	// For a file upload dstPath may be either a directory or a full
	// file path; splitRemote separates the two cases.
	var remoteTarget, topName string
	if info.IsDir() {
		remoteTarget = dstPath
		topName = filepath.Base(srcPath)
	} else {
		remoteTarget, topName = splitRemote(dstPath)
		if topName == "" {
			topName = filepath.Base(srcPath)
		}
	}
	remoteArgs := "-qt"
	if recursive {
		remoteArgs = "-qrt"
	}
	if err := session.Start(fmt.Sprintf("scp %s %s", remoteArgs, shellQuote(remoteTarget))); err != nil {
		return err
	}

	r := bufio.NewReader(stdout)
	if err := readAck(r, stderr); err != nil {
		return fmt.Errorf("initial ack: %w", err)
	}

	if info.IsDir() {
		if err := uploadTree(stdin, r, stderr, srcPath, topName, 0); err != nil {
			return err
		}
	} else {
		if err := uploadFile(stdin, r, stderr, srcPath, topName, info); err != nil {
			return err
		}
	}
	_ = stdin.Close()
	return session.Wait()
}

// uploadFile emits a single C-line + payload for one regular file.
// Non-regular entries (symlinks, sockets, devices) are skipped rather
// than errored, so a tree with a stray broken symlink still transfers
// — matching OpenSSH scp -r behavior.
func uploadFile(stdin io.Writer, r *bufio.Reader, stderr io.Reader, srcPath, remoteName string, info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return nil
	}
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()
	mode := info.Mode().Perm() &^ 0o7000 // strip setuid/setgid/sticky
	header := fmt.Sprintf("C%04o %d %s\n", mode, info.Size(), remoteName)
	if _, err := io.WriteString(stdin, header); err != nil {
		return err
	}
	if err := readAck(r, stderr); err != nil {
		return fmt.Errorf("header ack for %s: %w", remoteName, err)
	}
	if _, err := io.CopyN(stdin, f, info.Size()); err != nil {
		return err
	}
	if _, err := stdin.Write([]byte{0}); err != nil {
		return err
	}
	return readAck(r, stderr)
}

// uploadTree walks localDir depth-first, emitting D/E around each
// directory and C for each regular file. remoteName is the name of
// localDir on the remote side (at the current level).
func uploadTree(stdin io.Writer, r *bufio.Reader, stderr io.Reader, localDir, remoteName string, depth int) error {
	if depth > MaxRecursionDepth {
		return fmt.Errorf("scp: recursion deeper than %d levels at %s", MaxRecursionDepth, localDir)
	}
	info, err := os.Stat(localDir)
	if err != nil {
		return err
	}
	mode := info.Mode().Perm() &^ 0o7000
	if _, err := fmt.Fprintf(stdin, "D%04o 0 %s\n", mode, remoteName); err != nil {
		return err
	}
	if err := readAck(r, stderr); err != nil {
		return fmt.Errorf("dir ack for %s: %w", remoteName, err)
	}

	entries, err := os.ReadDir(localDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		entryPath := filepath.Join(localDir, e.Name())
		entryInfo, err := os.Lstat(entryPath)
		if err != nil {
			return err
		}
		switch {
		case entryInfo.IsDir():
			if err := uploadTree(stdin, r, stderr, entryPath, e.Name(), depth+1); err != nil {
				return err
			}
		case entryInfo.Mode().IsRegular():
			if err := uploadFile(stdin, r, stderr, entryPath, e.Name(), entryInfo); err != nil {
				return err
			}
		default:
			// Skip special files (symlinks, sockets, devices).
			continue
		}
	}
	if _, err := io.WriteString(stdin, "E\n"); err != nil {
		return err
	}
	return readAck(r, stderr)
}

// Download copies the remote path to the local dstPath. Pass
// recursive=true to pull a directory tree; a single file is fine
// either way. When recursive is true and dstPath does not exist,
// it is created as a directory at the top level.
func Download(client *ssh.Client, srcPath, dstPath string, recursive bool) error {
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

	remoteArgs := "-qf"
	if recursive {
		remoteArgs = "-qrf"
	}
	if err := session.Start(fmt.Sprintf("scp %s %s", remoteArgs, shellQuote(srcPath))); err != nil {
		return err
	}

	r := bufio.NewReader(stdout)
	if _, err := stdin.Write([]byte{0}); err != nil {
		return err
	}

	st := &receiverState{
		stdin:        stdin,
		stderr:       stderr,
		r:            r,
		pathStack:    []string{dstPath},
		fallbackName: filepath.Base(srcPath),
	}
	if err := st.run(); err != nil {
		return err
	}
	_ = stdin.Close()
	return session.Wait()
}

type receiverState struct {
	stdin        io.Writer
	stderr       io.Reader
	r            *bufio.Reader
	pathStack    []string // pathStack[len-1] is the current local directory
	fallbackName string   // used when remote sends an empty C-line name at the root
	pendingT     bool     // a T-line was just ack'd; the next directive must be C or D
}

func (st *receiverState) run() error {
	for {
		line, err := st.r.ReadString('\n')
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read directive: %w: %s", err, readStderrSnippet(st.stderr))
		}
		line = strings.TrimRight(line, "\n")
		if line == "" {
			continue
		}
		switch line[0] {
		case 'C':
			if err := st.handleC(line); err != nil {
				return err
			}
			st.pendingT = false
		case 'D':
			if err := st.handleD(line); err != nil {
				return err
			}
			st.pendingT = false
		case 'E':
			if err := st.handleE(); err != nil {
				return err
			}
			if len(st.pathStack) == 1 {
				return nil
			}
		case 'T':
			if st.pendingT {
				return fmt.Errorf("scp: consecutive T directives")
			}
			st.pendingT = true
			if _, err := st.stdin.Write([]byte{0}); err != nil {
				return err
			}
		case 0x01, 0x02:
			return fmt.Errorf("scp: %s (stderr: %s)",
				strings.TrimSpace(line[1:]), readStderrSnippet(st.stderr))
		default:
			return fmt.Errorf("unexpected SCP directive: %q", line)
		}
	}
}

func (st *receiverState) handleC(line string) error {
	mode, size, rn, err := parseCLine(line)
	if err != nil {
		return err
	}
	if _, err := st.stdin.Write([]byte{0}); err != nil {
		return err
	}

	// At the root of a non-recursive pull where dstPath is a
	// directory, use the validated remote name. Inside a recursive
	// descent, always nest under the current directory.
	var localTarget string
	if len(st.pathStack) == 1 {
		top := st.pathStack[0]
		if fi, statErr := os.Stat(top); statErr == nil && fi.IsDir() {
			if rn == "" {
				rn = st.fallbackName
			}
			localTarget = filepath.Join(top, rn)
		} else {
			localTarget = top
		}
	} else {
		localTarget = filepath.Join(st.pathStack[len(st.pathStack)-1], rn)
	}

	if err := refuseExistingSymlink(localTarget); err != nil {
		return err
	}
	out, err := os.OpenFile(localTarget, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.CopyN(out, st.r, size); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if b, err := st.r.ReadByte(); err != nil {
		return err
	} else if b != 0 {
		return fmt.Errorf("expected trailing 0 after file body, got %#x", b)
	}
	_, err = st.stdin.Write([]byte{0})
	return err
}

func (st *receiverState) handleD(line string) error {
	if len(st.pathStack) > MaxRecursionDepth {
		return fmt.Errorf("scp: remote tree exceeds %d levels of recursion", MaxRecursionDepth)
	}
	mode, rn, err := parseDLine(line)
	if err != nil {
		return err
	}

	// Top-level: if dstPath doesn't exist, create it as the receiving
	// dir; if it's already a directory, nest the tree inside it.
	var localDir string
	if len(st.pathStack) == 1 {
		top := st.pathStack[0]
		if fi, statErr := os.Stat(top); statErr == nil && fi.IsDir() {
			localDir = filepath.Join(top, rn)
		} else if os.IsNotExist(statErr) {
			localDir = top
		} else if statErr != nil {
			return statErr
		} else {
			return fmt.Errorf("scp: refuse to overwrite non-directory %s with directory %s", top, rn)
		}
	} else {
		localDir = filepath.Join(st.pathStack[len(st.pathStack)-1], rn)
	}

	if err := refuseExistingSymlink(localDir); err != nil {
		return err
	}
	if err := os.MkdirAll(localDir, mode); err != nil {
		return err
	}
	st.pathStack = append(st.pathStack, localDir)
	_, err = st.stdin.Write([]byte{0})
	return err
}

func (st *receiverState) handleE() error {
	if len(st.pathStack) <= 1 {
		// Stray E at the root. Ack and let run() exit.
		_, err := st.stdin.Write([]byte{0})
		return err
	}
	st.pathStack = st.pathStack[:len(st.pathStack)-1]
	_, err := st.stdin.Write([]byte{0})
	return err
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
		if errMsg := readStderrSnippet(stderr); errMsg != "" {
			return fmt.Errorf("scp: %s (stderr: %s)", strings.TrimSpace(msg), errMsg)
		}
		return fmt.Errorf("scp: %s", strings.TrimSpace(msg))
	default:
		return fmt.Errorf("unexpected ack byte %#x", b)
	}
}

// readStderrSnippet drains up to 4 KiB of a remote stderr stream so a
// malicious server can't exhaust our memory by piping gigabytes to
// stderr before we report an error.
func readStderrSnippet(stderr io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(stderr, 4<<10))
	return strings.TrimSpace(string(b))
}

// refuseExistingSymlink blocks the TOCTOU-narrow case where the local
// path is an attacker-planted symlink that would redirect a write or
// an mkdir outside the destination tree. If the path doesn't exist
// this is a no-op.
func refuseExistingSymlink(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil // not present: nothing to check
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("scp: refuse to write through existing symlink %s", p)
	}
	return nil
}

// parseDLine parses "D<mode> 0 <name>" as sent by a recursive scp -f
// when descending into a directory.
func parseDLine(line string) (os.FileMode, string, error) {
	mode, _, name, err := parseHeader(line, 'D')
	return mode, name, err
}

// parseCLine parses "C<mode> <size> <name>" and returns (mode, size, name).
func parseCLine(line string) (os.FileMode, int64, string, error) {
	return parseHeader(line, 'C')
}

// parseHeader parses a C-line or D-line: "<prefix><mode> <size> <name>".
// Sharing the code keeps the setuid/setgid/sticky guard and the
// validateSCPFilename call at a single audit point.
func parseHeader(line string, prefix byte) (os.FileMode, int64, string, error) {
	if len(line) == 0 || line[0] != prefix {
		return 0, 0, "", fmt.Errorf("expected %c-line, got %q", prefix, line)
	}
	parts := strings.SplitN(line[1:], " ", 3)
	if len(parts) != 3 {
		return 0, 0, "", fmt.Errorf("malformed %c-line: %q", prefix, line)
	}
	mode, err := strconv.ParseUint(parts[0], 8, 32)
	if err != nil {
		return 0, 0, "", fmt.Errorf("bad mode %q: %w", parts[0], err)
	}
	if mode&0o7000 != 0 {
		return 0, 0, "", fmt.Errorf("refusing setuid/setgid/sticky mode: %#o", mode)
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

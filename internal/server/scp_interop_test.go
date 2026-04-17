package server_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestSystemSCPUploadAndDownload verifies that the system `scp`
// client can push and pull files through gosshd using the legacy
// SCP protocol (which is just exec("scp -t/-f")). gosshd needs no
// special code for this — as long as AllowExec is on and scp is
// installed on the "server" side of the connection, it works.
func TestSystemSCPUploadAndDownload(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	if _, err := exec.LookPath("scp"); err != nil {
		t.Skip("scp not installed")
	}
	h := startServer(t, nil)

	// Upload: create a local file, scp it "to" the server, then
	// verify the file landed where we expect.
	workdir := t.TempDir()
	localSrc := filepath.Join(workdir, "src.bin")
	payload := bytes.Repeat([]byte("the-quick-brown-fox-"), 1024) // ~20KB
	if err := os.WriteFile(localSrc, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	remoteDest := filepath.Join(workdir, "dst.bin")

	sshBin := requireSSHClient(t)
	_ = sshBin
	scpArgs := []string{
		"-i", h.UserKeyPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "UserKnownHostsFile=" + h.KnownHosts,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "BatchMode=yes",
		"-O", // force legacy scp protocol (not sftp) — works via exec
		"-P", h.Port,
		localSrc,
		fmt.Sprintf("testuser@%s:%s", h.Host, remoteDest),
	}
	cmd := exec.Command("scp", scpArgs...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("scp upload: %v\n%s", err, stderr.String())
	}
	got, err := os.ReadFile(remoteDest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("upload content mismatch (%d vs %d bytes)", len(got), len(payload))
	}

	// Download: pull the remote file back to a new local path.
	localDst := filepath.Join(workdir, "downloaded.bin")
	cmdDL := exec.Command("scp", append(scpArgs[:len(scpArgs)-2],
		fmt.Sprintf("testuser@%s:%s", h.Host, remoteDest),
		localDst,
	)...)
	var dlErr bytes.Buffer
	cmdDL.Stderr = &dlErr
	if err := cmdDL.Run(); err != nil {
		t.Fatalf("scp download: %v\n%s", err, dlErr.String())
	}
	got2, err := os.ReadFile(localDst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got2, payload) {
		t.Fatalf("download content mismatch")
	}
}

package server

import (
	"fmt"
	"io"
	"os/exec"

	"github.com/oscar/gossh/internal/pty"
)

// runPTY starts the shell attached to a fresh pseudo-terminal and
// bridges data in both directions between the SSH channel and the
// pty master.
func (st *sessionState) runPTY(command string, wantShell bool) {
	shell := st.server.cfg.Shell
	if shell == "" {
		shell = "/bin/sh"
	}
	args := []string{}
	if command == "" {
		// Interactive login-ish shell. We pass `-l` so it sources
		// the user's profile; this matches what OpenSSH does for a
		// plain `ssh host` with pty.
		args = []string{"-l"}
		_ = wantShell
	} else {
		args = []string{"-c", command}
	}
	cmd := exec.CommandContext(st.ctx, shell, args...)
	cmd.Env = st.finalEnv(true)

	ses, err := pty.Start(cmd, st.ptyReq.Rows, st.ptyReq.Cols)
	if err != nil {
		fmt.Fprintf(st.ch.Stderr(), "gossh: pty start: %v\n", err)
		_ = sendExitStatus(st.ch, 127)
		_ = st.ch.Close()
		return
	}

	// Resize watcher.
	go func() {
		for w := range st.resize {
			_ = ses.Resize(w.Rows, w.Cols)
		}
	}()

	// channel <- pty (output)
	copyDone := make(chan struct{})
	go func() {
		defer close(copyDone)
		_, _ = io.Copy(st.ch, ses.Master)
	}()
	// channel -> pty (input). When the client closes the channel,
	// this copy returns; we then close the pty master so the shell
	// sees EOF on stdin. We also send SIGHUP if that doesn't kick it.
	go func() {
		_, _ = io.Copy(ses.Master, st.ch)
		_ = ses.Master.Close()
	}()

	waitErr := cmd.Wait()
	<-copyDone
	_ = ses.Close()
	_ = st.ch.CloseWrite()
	_ = sendExitStatus(st.ch, exitStatus(waitErr))
	_ = st.ch.Close()
}

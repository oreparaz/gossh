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
func (st *sessionState) runPTY(command string) {
	shell := st.server.cfg.Shell
	if shell == "" {
		shell = "/bin/sh"
	}
	args := []string{}
	if command == "" {
		// Interactive login shell. `-l` sources the user's profile,
		// matching what OpenSSH does for `ssh host` with pty.
		args = []string{"-l"}
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
	st.setChildCmd(cmd)
	defer st.setChildCmd(nil)

	// Resize watcher.
	go func() {
		for w := range st.resize {
			_ = ses.Resize(w.Rows, w.Cols)
		}
	}()

	// channel <- pty (output). Closing ses.Master (after Wait
	// returns) makes this io.Copy return.
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		_, _ = io.Copy(st.ch, ses.Master)
	}()
	// channel -> pty (input). Do NOT close ses.Master from this
	// goroutine: the child may still be writing to the pty slave,
	// and closing master from under it makes the slave side fail
	// with EIO, causing the command to exit non-zero.
	go func() {
		_, _ = io.Copy(ses.Master, st.ch)
	}()

	waitErr := cmd.Wait()
	st.exitCode = exitStatus(waitErr)
	_ = ses.Close() // master close → outputDone unblocks → send exit
	<-outputDone
	_ = st.ch.CloseWrite()
	_ = sendExitStatus(st.ch, st.exitCode)
	_ = st.ch.Close()
}

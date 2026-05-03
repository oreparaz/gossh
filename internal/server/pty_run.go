package server

import (
	"fmt"
	"io"
	"os/exec"

	"github.com/oreparaz/gossh/internal/pty"
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

	// Resize watcher. resizeStop lets runPTY retire this goroutine
	// deterministically before ses.Close — otherwise a window-change
	// that arrives as the session is tearing down could call
	// pty.Setsize on an already-closed fd (race on os.File.Fd).
	resizeStop := make(chan struct{})
	resizeDone := make(chan struct{})
	go func() {
		defer close(resizeDone)
		for {
			select {
			case w, ok := <-st.resize:
				if !ok {
					return
				}
				_ = ses.Resize(w.Rows, w.Cols)
			case <-resizeStop:
				return
			}
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
	// Retire the resize watcher before the master is closed.
	close(resizeStop)
	<-resizeDone
	_ = ses.Close() // master close → outputDone unblocks → send exit
	<-outputDone
	// Same ordering rationale as runPipe: enqueue exit-status before
	// CloseWrite/Close so the client's Session.wait() observes the
	// request before the requests channel terminates.
	_ = sendExitStatus(st.ch, st.exitCode)
	_ = st.ch.CloseWrite()
	_ = st.ch.Close()
}

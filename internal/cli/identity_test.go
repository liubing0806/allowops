package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

func TestRPCErrorReportsPossibleCommitWithoutEchoingServerSecrets(t *testing.T) {
	err := connect.NewError(connect.CodeUnavailable, errors.New("provider-password-must-not-leak"))
	detail, detailErr := connect.NewErrorDetail(&v1.ErrorDetail{Reason: "AUDIT_RESULT_UNAVAILABLE"})
	if detailErr != nil {
		t.Fatal(detailErr)
	}
	err.AddDetail(detail)
	message := rpcError(err).Error()
	if !strings.Contains(message, "may have committed") || strings.Contains(message, "provider-password") {
		t.Fatalf("CLI audit failure message=%q", message)
	}
}

// The CLI cancels the command context on SIGINT instead of exiting, so the
// password prompt must end with it and restore terminal echo.
func TestPasswordPromptEndsWithCommandContext(t *testing.T) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	defer master.Close()
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.Close()
	ctx, cancel := context.WithCancel(context.Background())
	c := &cobra.Command{}
	c.SetContext(ctx)
	c.SetIn(terminal)
	c.SetErr(io.Discard)
	done := make(chan error, 1)
	go func() {
		_, err := readPassword(c, false)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled prompt returned a password")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("password prompt kept waiting after the command context ended")
	}
	state, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if state.Lflag&unix.ECHO == 0 {
		t.Error("terminal echo was not restored")
	}
}

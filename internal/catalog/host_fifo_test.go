package catalog

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestHostRejectsFIFOWithoutWriter(t *testing.T) {
	for _, mode := range []string{"exec", "fallback", "step", "interpreter"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sh")
			if err := syscall.Mkfifo(path, 0700); err != nil {
				t.Fatal(err)
			}
			a := Action{Name: "fifo", Description: "fifo", Risk: "read", Timeout: "1s", MaxOutput: 1024}
			switch mode {
			case "exec":
				a.Exec = []any{path}
			case "fallback":
				a.Exec = []any{path + "-missing"}
				a.ExecFallbacks = []string{path}
			case "step":
				a.Steps = []Step{{Name: "fifo", Exec: []any{path}}}
			case "interpreter":
				a.Script = &Script{File: "script.sh", Interpreter: path, Content: []byte("true"), SHA256: scriptDigest([]byte("true"))}
			}
			a.AllowInterpreter = true
			if _, err := ValidateAction(a); err != nil {
				t.Fatal(err)
			}
			done := make(chan HostSupport, 1)
			go func() { done <- CheckHost(a) }()
			select {
			case support := <-done:
				if support.Supported {
					t.Fatal("FIFO accepted as executable")
				}
			case <-time.After(300 * time.Millisecond):
				// Release a blocking reader before reporting the product failure.
				f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("FIFO reader cleanup failed")
				}
				t.Error("CheckHost blocked on FIFO without writer; want prompt unsupported")
			}
		})
	}
}

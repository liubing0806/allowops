package executor

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/liubing0806/allowops/internal/catalog"
)

// writeScript refuses an existing path, including a symlink. The private directory
// is created by MkdirTemp (0700) and removed after the process group terminates.
func writeScript(dir string, content []byte) (string, error) {
	path := filepath.Join(dir, "script")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return "", err
	}
	_, writeErr := f.Write(content)
	closeErr := f.Close()
	if writeErr != nil {
		return "", writeErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return path, nil
}

func prepareScript(s catalog.Script, args []string) ([]string, func(), error) {
	dir, err := os.MkdirTemp("", "allowops-script-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path, err := writeScript(dir, s.Content)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	argv := []string{s.Interpreter}
	if strings.HasPrefix(strings.ToLower(filepath.Base(s.Interpreter)), "python") {
		argv = append(argv, "-I")
	}
	argv = append(argv, path)
	argv = append(argv, args...)
	return argv, cleanup, nil
}

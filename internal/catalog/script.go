package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func scriptDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func validateScript(s Script) error {
	if s.File == "" || filepath.IsAbs(s.File) || strings.ContainsAny(s.File, "\x00\r\n\\") {
		return fmt.Errorf("script.file must be a relative catalog path")
	}
	for _, component := range strings.Split(s.File, "/") {
		if component == ".." {
			return fmt.Errorf("script.file traversal forbidden")
		}
	}
	if !filepath.IsAbs(s.Interpreter) || !IsInterpreter(s.Interpreter) {
		return fmt.Errorf("script.interpreter must be an absolute interpreter path")
	}
	if s.SHA256 != scriptDigest(s.Content) {
		return fmt.Errorf("script content digest mismatch")
	}
	return nil
}

func loadScript(dir string, s *Script) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.OpenFile(s.File, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("script must be a regular file within catalog")
	}
	s.Content, err = io.ReadAll(f)
	if err != nil {
		return err
	}
	s.SHA256 = scriptDigest(s.Content)
	return nil
}

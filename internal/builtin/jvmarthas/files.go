package jvmarthas

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
)

// maxFileBytes bounds the size of one Arthas file; the jars are a few megabytes.
const maxFileBytes = 64 << 20

// verifyFiles checks that dir in the file system of root holds the five files with the given SHA-256 values.
// The files are the ones the JVM will load: the path is resolved inside root, a symbolic link at the end
// of it is refused, and nothing is written.
func verifyFiles(root Files, dir string, want map[string]string) error {
	for _, name := range FileNames {
		full := path.Join(dir, name)
		sum, err := fileSum(root, full)
		if err != nil {
			return fmt.Errorf("arthas file %s: %w", full, err)
		}
		if sum != want[name] {
			return fmt.Errorf("arthas file %s has SHA-256 %s, the catalog expects %s", full, sum, want[name])
		}
	}
	return nil
}

func fileSum(root Files, full string) (string, error) {
	f, err := root.OpenFile(full)
	if err != nil {
		if pe, ok := err.(*fs.PathError); ok {
			err = pe.Err
		}
		return "", fmt.Errorf("cannot be opened in the file system of the target: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return "", err
	}
	if n > maxFileBytes {
		return "", fmt.Errorf("is larger than %d bytes", maxFileBytes)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CheckInstalled reports whether the five Arthas files are in dir on this host. It looks at
// the host's file system only; the check before an attach reads the file system of the target.
func CheckInstalled(dir string) error {
	for _, name := range FileNames {
		full := filepath.Join(dir, name)
		info, err := os.Lstat(full)
		if err != nil {
			return fmt.Errorf("the Arthas package is not installed: %w", err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("the Arthas package is not installed: %s is not a regular file", full)
		}
	}
	return nil
}

//go:build unix

package credfile

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// Read opens path and checks the file on the opened descriptor. It rejects
// symbolic links in the last path component, anything but a regular file owned
// by root with mode 0600, files over 16 KiB, and malformed JSON. Errors never
// contain the file content.
func Read(path string) (Credential, error) {
	var c Credential
	// O_NONBLOCK prevents a FIFO/device path from blocking before fstat rejects it.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return c, errors.New("cannot open credential file")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return c, errors.New("cannot inspect credential file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode() != 0600 {
		return c, errors.New("credential file must be a regular root-owned file with mode 0600")
	}
	if info.Size() > 16384 {
		return c, errors.New("credential file is too large")
	}
	return Decode(io.LimitReader(f, 16385))
}

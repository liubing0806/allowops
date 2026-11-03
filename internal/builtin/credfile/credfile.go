// Package credfile reads the host-local database credential file shared by the
// database builtins: a root-owned, mode 0600 regular file that holds one JSON
// object with username and password.
package credfile

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"
)

// Credential is the content of a credential file.
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

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

// Decode parses exactly one JSON object with the string fields username and
// password. The username must not be empty; the password may be.
func Decode(r io.Reader) (Credential, error) {
	var fields struct {
		Username *string `json:"username"`
		Password *string `json:"password"`
	}
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(&fields); err != nil || fields.Username == nil || *fields.Username == "" || fields.Password == nil {
		return Credential{}, errors.New("credential must contain JSON username and password strings")
	}
	if d.Decode(new(any)) != io.EOF {
		return Credential{}, errors.New("credential must contain exactly one JSON object")
	}
	return Credential{Username: *fields.Username, Password: *fields.Password}, nil
}

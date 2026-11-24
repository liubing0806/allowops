//go:build unix

package apiclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"
)

// readCredential applies the same file checks as the Redis and MySQL handlers.
// Error text never includes file content.
func readCredential(path string) (credential, error) {
	var c credential
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return c, errors.New("cannot open API credential file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return c, errors.New("cannot stat API credential file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return c, errors.New("API credential file must be owned by root")
	}
	if info.Mode() != 0600 {
		return c, errors.New("API credential file must be regular with mode 0600")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCredentialBytes+1))
	if err != nil || len(data) > maxCredentialBytes {
		return c, errors.New("cannot read API credential file or size exceeds 16KiB")
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return c, errors.New("API credential must contain one JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return credential{}, errors.New("invalid API credential JSON")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return credential{}, errors.New("API credential must contain one JSON object")
	}
	return c, nil
}

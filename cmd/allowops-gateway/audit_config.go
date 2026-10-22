package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/liubing0806/allowops/internal/gateway/audit"
)

func (c configuration) auditConfig(log io.Writer) (audit.Config, error) {
	if c.Audit.CursorKeyFile == "" {
		fmt.Fprintln(log, "audit.cursor_key_file not configured; using a process-local random key; pagination cursors will be invalid after restart or across instances")
		return audit.Config{}, nil
	}
	f, err := os.Open(c.Audit.CursorKeyFile)
	if err != nil {
		return audit.Config{}, errors.New("read audit cursor key file")
	}
	defer f.Close()
	key, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(key) != 32 {
		return audit.Config{}, errors.New("audit cursor key file must contain exactly 32 raw bytes")
	}
	return audit.Config{CursorKey: key}, nil
}

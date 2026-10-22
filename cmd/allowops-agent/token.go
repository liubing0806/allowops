package main

import (
	"errors"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// Keep all join-token option semantics here, including the legacy source.
func readJoinToken(cmd *cobra.Command) (string, error) {
	sources := 0
	for _, name := range []string{"token", "token-file", "token-stdin"} {
		if cmd.Flags().Changed(name) {
			sources++
		}
	}
	if sources != 1 {
		return "", errors.New("exactly one of --token, --token-file or --token-stdin required")
	}
	token, _ := cmd.Flags().GetString("token")
	path, _ := cmd.Flags().GetString("token-file")
	var source io.Reader
	if cmd.Flags().Changed("token-file") {
		f, err := os.Open(path)
		if err != nil {
			return "", errors.New("read join token file")
		}
		defer f.Close()
		source = f
	} else if cmd.Flags().Changed("token-stdin") {
		enabled, _ := cmd.Flags().GetBool("token-stdin")
		if !enabled {
			return "", errors.New("--token-stdin must be true")
		}
		source = cmd.InOrStdin()
	} else {
		source = strings.NewReader(token)
	}
	data, err := io.ReadAll(io.LimitReader(source, 4097))
	if err != nil {
		return "", errors.New("read join token")
	}
	if len(data) > 4096 {
		return "", errors.New("join token exceeds 4 KiB")
	}
	token = strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("join token must not be empty")
	}
	return token, nil
}

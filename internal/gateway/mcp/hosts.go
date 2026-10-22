package mcp

import (
	"errors"
	"strings"
)

// A27: empty conditions use the same P5B per-host visibility and pagination.
func emptyHostSearch() error {
	return nil
}

func validateHostSearchSelection(hostname, selector string) error {
	if hostname == "" && selector == "" {
		return emptyHostSearch()
	}
	if hostname != "" && selector != "" {
		return errors.New("hosts_search allowed: hostname or selector, not both")
	}
	if hostname != "" {
		if strings.TrimSpace(hostname) == "" || strings.ContainsAny(hostname, "\x00\r\n") {
			return errors.New("hostname allowed: nonempty hostname without CR/LF/NUL")
		}
		return nil
	}
	return validateSelector(selector)
}

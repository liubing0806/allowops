package mcp

import (
	"errors"
	"strings"
)

// Empty conditions list every host the caller may view, with the same per-host visibility and pagination as other host queries (design A27, P5B).
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

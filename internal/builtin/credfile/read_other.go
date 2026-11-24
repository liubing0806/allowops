//go:build !unix

package credfile

import "errors"

// Read is only supported on Unix hosts where file ownership and mode 0600 can be enforced.
func Read(string) (Credential, error) {
	return Credential{}, errors.New("credential files require Unix host support")
}

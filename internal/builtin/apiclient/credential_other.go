//go:build !unix

package apiclient

import "errors"

func readCredential(string) (credential, error) {
	return credential{}, errors.New("API credential files require Unix host support")
}

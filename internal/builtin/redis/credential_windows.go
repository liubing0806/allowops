package redis

import "errors"

func readCredential(string) (credential, error) {
	return credential{}, errors.New("redis credential files require Unix permissions")
}

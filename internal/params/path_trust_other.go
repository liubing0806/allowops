//go:build !unix

package params

import "errors"

func lstatOwner(string) (entryOwner, error) {
	return entryOwner{}, errors.New("no ownership information")
}

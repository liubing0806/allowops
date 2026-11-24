//go:build unix

package params

import (
	"errors"
	"os"
	"syscall"
)

func lstatOwner(path string) (entryOwner, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return entryOwner{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return entryOwner{}, errors.New("no ownership information")
	}
	return entryOwner{mode: info.Mode(), uid: stat.Uid}, nil
}

//go:build unix

package catalog

import (
	"syscall"

	"golang.org/x/sys/unix"
)

const openNonBlock = syscall.O_NONBLOCK

func checkExecutableAccess(path string) error {
	return unix.Faccessat(unix.AT_FDCWD, path, unix.X_OK, unix.AT_EACCESS)
}

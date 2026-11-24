//go:build unix

package catalog

import "golang.org/x/sys/unix"

func checkExecutableAccess(path string) error {
	return unix.Faccessat(unix.AT_FDCWD, path, unix.X_OK, unix.AT_EACCESS)
}

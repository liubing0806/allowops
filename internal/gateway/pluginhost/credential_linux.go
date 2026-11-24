//go:build linux

package pluginhost

import (
	"errors"

	"golang.org/x/sys/unix"
)

func openProjected(dir int, base string) (int, error) {
	fd, err := unix.Openat2(dir, base, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_IN_ROOT,
	})
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
		return -1, errProjected
	}
	if err != nil {
		return -1, errCredentialRead
	}
	return fd, nil
}

//go:build unix

package logquery

import (
	"io/fs"
	"syscall"
)

const openNonBlock = syscall.O_NONBLOCK

func fileIdentity(info fs.FileInfo) ([2]uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return [2]uint64{}, false
	}
	return [2]uint64{uint64(stat.Dev), stat.Ino}, true
}

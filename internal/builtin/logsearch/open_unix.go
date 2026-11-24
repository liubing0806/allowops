//go:build unix

package logsearch

import "syscall"

const openNonBlock = syscall.O_NONBLOCK

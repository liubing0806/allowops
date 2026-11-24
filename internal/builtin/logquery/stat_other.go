//go:build !unix

package logquery

import "io/fs"

const openNonBlock = 0

func fileIdentity(fs.FileInfo) ([2]uint64, bool) {
	return [2]uint64{}, false
}

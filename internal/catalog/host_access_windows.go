package catalog

import "os"

const openNonBlock = 0

func checkExecutableAccess(path string) error {
	_, err := os.Stat(path)
	return err
}

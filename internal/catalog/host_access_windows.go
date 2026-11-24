package catalog

import "os"

func checkExecutableAccess(path string) error {
	_, err := os.Stat(path)
	return err
}

package catalog

import (
	"errors"
	"os"
)

func openCatalogScript(root *os.Root, name string) (*os.File, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("script must be a regular file within catalog")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !os.SameFile(info, opened) {
		f.Close()
		return nil, errors.New("script changed while opening")
	}
	return f, nil
}

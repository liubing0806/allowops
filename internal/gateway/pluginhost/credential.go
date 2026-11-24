package pluginhost

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	"golang.org/x/sys/unix"
)

const maxCredentialBytes = 16 << 10

var (
	credentialRef          = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	errCredentialRef       = errors.New("plugin credential: invalid reference")
	errCredentialConfig    = errors.New("plugin credential: invalid configuration")
	errCredentialDirectory = errors.New("plugin credential: invalid directory")
	errCredentialMissing   = errors.New("plugin credential: unknown reference")
	errCredentialRead      = errors.New("plugin credential: cannot read file")
	errCredentialFile      = errors.New("plugin credential: invalid file")
	errCredentialSize      = errors.New("plugin credential: file exceeds size limit")
	errProjected           = errors.New("plugin credential: projected volume requires openat2")
)

type credentialFile struct {
	dir  int
	base string
}

type credentialFiles struct {
	files     map[string]credentialFile
	projected bool
}

func validateCredentials(config Config) error {
	if len(config.Credentials) > 16 {
		return errCredentialConfig
	}
	for ref, path := range config.Credentials {
		if !credentialRef.MatchString(ref) {
			return errCredentialRef
		}
		if !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) {
			return errCredentialConfig
		}
	}
	return nil
}

func newCredentialFiles(config Config) (*credentialFiles, error) {
	if err := validateCredentials(config); err != nil {
		return nil, err
	}
	files := &credentialFiles{files: make(map[string]credentialFile), projected: config.AllowProjectedCredentials}
	for ref, path := range config.Credentials {
		path = filepath.Clean(path)
		dir, err := openCredentialDirectory(filepath.Dir(path), files.projected)
		if err != nil {
			files.close()
			return nil, err
		}
		files.files[ref] = credentialFile{dir, filepath.Base(path)}
	}
	return files, nil
}

func openCredentialDirectory(path string, projected bool) (int, error) {
	dir, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, errCredentialDirectory
	}
	if projected {
		// Probe support at startup. A credential may be rotated after startup.
		probe, err := openProjected(dir, ".")
		if err != nil {
			unix.Close(dir)
			return -1, err
		}
		unix.Close(probe)
		return dir, nil
	}
	var stat unix.Stat_t
	if err := unix.Fstat(dir, &stat); err != nil ||
		(stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || stat.Mode&0o002 != 0 {
		unix.Close(dir)
		return -1, errCredentialDirectory
	}
	return dir, nil
}

func (c *credentialFiles) close() {
	for _, f := range c.files {
		unix.Close(f.dir)
	}
}

func (c *credentialFiles) read(ref string) ([]byte, error) {
	if !credentialRef.MatchString(ref) {
		return nil, errCredentialRef
	}
	f, ok := c.files[ref]
	if !ok {
		return nil, errCredentialMissing
	}
	var fd int
	var err error
	if c.projected {
		fd, err = openProjected(f.dir, f.base)
	} else {
		fd, err = unix.Openat(f.dir, f.base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	}
	if err != nil {
		if errors.Is(err, errProjected) {
			return nil, errProjected
		}
		return nil, errCredentialRead
	}
	file := os.NewFile(uintptr(fd), "plugin credential")
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || !allowedCredentialMode(stat) {
		return nil, errCredentialFile
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCredentialBytes+1))
	if err != nil {
		return nil, errCredentialRead
	}
	if len(data) > maxCredentialBytes {
		return nil, errCredentialSize
	}
	return data, nil
}

func allowedCredentialMode(stat unix.Stat_t) bool {
	mode := stat.Mode & 0o7777
	if stat.Uid == uint32(os.Geteuid()) {
		return mode == 0o400 || mode == 0o600
	}
	if stat.Uid != 0 || mode != 0o440 && mode != 0o640 {
		return false
	}
	if stat.Gid == uint32(os.Getegid()) {
		return true
	}
	groups, err := os.Getgroups()
	return err == nil && slices.Contains(groups, int(stat.Gid))
}

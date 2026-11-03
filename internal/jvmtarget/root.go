package jvmtarget

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	// ErrSymlink is returned when the last path component is a symbolic link.
	ErrSymlink = errors.New("path ends in a symbolic link")
	// ErrNotRegular is returned when a file to read is not a regular file.
	ErrNotRegular = errors.New("not a regular file")
	// ErrNotSocket is returned when a path that must be a socket is something else.
	ErrNotSocket = errors.New("not a socket")
)

// A Root resolves paths of another mount namespace through /proc/<pid>/root.
// Following that link and then resolving the path by name is unsafe: the kernel
// keeps the caller's root for absolute symbolic links and ".." at the top, so
// a link in the container such as /tmp -> /etc, or /tmp -> ../../etc, leads to
// the host's directory. Root resolves every path as if the directory were /.
//
// The kernel does that with openat2(RESOLVE_IN_ROOT), available from Linux 5.6.
// Before that (CentOS 7 has 3.10) resolve walks the path one component at a
// time with O_PATH|O_NOFOLLOW, reading symbolic links itself and handling ".."
// with a stack of directory descriptors, so no step ever uses a name the
// container could redirect.
//
// Nothing is written. Create makes an empty file, for the attach trigger file, and
// special files are never opened: opening a device node or FIFO that a container made
// can have side effects on the host.

const (
	// maxPath is the kernel's PATH_MAX; it also bounds a path after links are expanded.
	maxPath = 4096
	// maxLinks is the kernel's limit on symbolic links per lookup.
	maxLinks = 40
)

// forceFallback makes Root skip openat2, to exercise the code used on kernels before 5.6.
var forceFallback bool

var (
	openat2Once   sync.Once
	openat2Usable bool
)

// openat2Available reports whether the kernel has openat2 (Linux 5.6) and the
// process may call it; some container seccomp profiles refuse it.
func openat2Available() bool {
	openat2Once.Do(func() {
		fd, err := unix.Openat2(unix.AT_FDCWD, "/", &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT})
		if err == nil {
			unix.Close(fd)
		}
		openat2Usable = err == nil
	})
	return openat2Usable
}

// Root is a directory below which paths are resolved, as if it were /.
type Root struct{ fd int }

// OpenRoot opens dir, which may itself be a symbolic link (/proc/<pid>/root is one).
func OpenRoot(dir string) (*Root, error) {
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: dir, Err: err}
	}
	return &Root{fd: fd}, nil
}

// Close releases the directory.
func (r *Root) Close() error { return unix.Close(r.fd) }

// OpenFile opens a regular file for reading. Symbolic links in the middle of
// the path are followed inside the root; one at the end is an error
// (ErrSymlink), as is anything but a regular file (ErrNotRegular).
func (r *Root) OpenFile(path string) (*os.File, error) {
	return r.open(path, unix.S_IFREG, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, false)
}

// OpenDir opens a directory for listing. A symbolic link at the end of the path
// is followed inside the root, like one in the middle (a container may make
// /tmp a link to another directory of its own).
func (r *Root) OpenDir(path string) (*os.File, error) {
	return r.open(path, unix.S_IFDIR, unix.O_RDONLY|unix.O_DIRECTORY, true)
}

// validPath rejects what no lookup accepts. A trailing slash is rejected because it would
// make the kernel follow a symbolic link at the end.
func validPath(path string) error {
	if path == "" || len(path) > maxPath || strings.ContainsRune(path, 0) || strings.HasSuffix(path, "/") {
		return unix.EINVAL
	}
	return nil
}

func (r *Root) open(path string, kind uint32, flags int, followLast bool) (*os.File, error) {
	fail := func(err error) (*os.File, error) { return nil, &os.PathError{Op: "open", Path: path, Err: err} }
	if err := validPath(path); err != nil {
		return fail(err)
	}
	// O_PATH first: it opens nothing, so a FIFO or device cannot do anything
	// before the type is known.
	pfd, err := r.resolve(path, followLast)
	if err != nil {
		return fail(err)
	}
	defer unix.Close(pfd)
	var st unix.Stat_t
	if err := unix.Fstat(pfd, &st); err != nil {
		return fail(err)
	}
	switch st.Mode & unix.S_IFMT {
	case kind:
	case unix.S_IFLNK:
		return fail(ErrSymlink)
	default:
		if kind == unix.S_IFDIR {
			return fail(unix.ENOTDIR)
		}
		return fail(ErrNotRegular)
	}
	// Reopen the inode the O_PATH descriptor holds. This does not go through
	// any name the container controls.
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", pfd), flags|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(err)
	}
	return os.NewFile(uintptr(fd), path), nil
}

// Stat describes path. A symbolic link at the end of the path is described itself, not
// followed, unless follow is set; links elsewhere are followed inside the root.
func (r *Root) Stat(path string, follow bool) (unix.Stat_t, error) {
	var st unix.Stat_t
	if err := validPath(path); err != nil {
		return st, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	fd, err := r.resolve(path, follow)
	if err != nil {
		return st, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	defer unix.Close(fd)
	if err := unix.Fstat(fd, &st); err != nil {
		return st, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	return st, nil
}

// OpenSocket returns an O_PATH descriptor of the socket at path. It fails with ErrSymlink when
// the path ends in a symbolic link, with ErrNotSocket for any other file type and with
// errForeignOwner when uid does not own the socket. The caller closes the descriptor.
// Connecting to /proc/self/fd/<fd> reaches the inode that was checked, not whatever the
// name leads to later. Connecting through /proc/<pid>/root/<path> would resolve the
// absolute symbolic links of the container in the host's root.
func (r *Root) OpenSocket(path string, uid uint32) (int, error) {
	fail := func(err error) (int, error) { return -1, &os.PathError{Op: "open", Path: path, Err: err} }
	if err := validPath(path); err != nil {
		return fail(err)
	}
	fd, err := r.resolve(path, false)
	if err != nil {
		return fail(err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return fail(err)
	}
	switch {
	case st.Mode&unix.S_IFMT == unix.S_IFLNK:
		err = ErrSymlink
	case st.Mode&unix.S_IFMT != unix.S_IFSOCK:
		err = ErrNotSocket
	case st.Uid != uid:
		err = errForeignOwner
	}
	if err != nil {
		unix.Close(fd)
		return fail(err)
	}
	return fd, nil
}

// A CreatedFile is an empty file made by Root.Create. It keeps the directory open, so Remove
// deletes the name in the directory where the file was made, whatever happened to the path
// since. A CreatedFile is not safe for concurrent use.
type CreatedFile struct {
	// Path is the path in the root, for messages.
	Path    string
	dirfd   int
	name    string
	removed bool
}

// Create makes the file name, owned by uid and gid, in the directory dir of the root. A
// symbolic link at the end of dir is followed inside the root, like one in the middle. The
// file must not exist: a name that exists, as a file or as a link, fails with EEXIST, and the
// existing file is never opened or changed.
func (r *Root) Create(dir, name string, mode, uid, gid uint32) (*CreatedFile, error) {
	path := strings.TrimRight(dir, "/") + "/" + name
	fail := func(err error) (*CreatedFile, error) { return nil, &os.PathError{Op: "create", Path: path, Err: err} }
	if name == "" || name == "." || name == ".." || len(name) > 255 || strings.ContainsAny(name, "/\x00") {
		return fail(unix.EINVAL)
	}
	if dir == "/" {
		dir = "." // the root itself
	} else if err := validPath(dir); err != nil {
		return fail(err)
	}
	dirfd, err := r.resolve(dir, true)
	if err != nil {
		return fail(err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(dirfd, &st); err != nil {
		unix.Close(dirfd)
		return fail(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		unix.Close(dirfd)
		return fail(unix.ENOTDIR)
	}
	fd, err := unix.Openat(dirfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		unix.Close(dirfd)
		return fail(err)
	}
	err = unix.Fchown(fd, int(uid), int(gid))
	unix.Close(fd)
	if err != nil {
		unix.Unlinkat(dirfd, name, 0)
		unix.Close(dirfd)
		return fail(err)
	}
	return &CreatedFile{Path: path, dirfd: dirfd, name: name}, nil
}

// Remove deletes the file. A file that is already gone is not an error. Remove can be called again.
func (c *CreatedFile) Remove() error {
	if c == nil || c.removed {
		return nil
	}
	err := unix.Unlinkat(c.dirfd, c.name, 0)
	unix.Close(c.dirfd)
	c.removed = true
	if err != nil && err != unix.ENOENT {
		return &os.PathError{Op: "remove", Path: c.Path, Err: err}
	}
	return nil
}

// resolve returns an O_PATH descriptor for path, resolved in the root. A
// symbolic link in the last component is followed (inside the root) only with
// followLast; otherwise the descriptor is that of the link itself.
func (r *Root) resolve(path string, followLast bool) (int, error) {
	if !forceFallback && openat2Available() {
		flags := unix.O_PATH | unix.O_CLOEXEC
		if !followLast {
			flags |= unix.O_NOFOLLOW
		}
		fd, err := unix.Openat2(r.fd, path, &unix.OpenHow{
			Flags:   uint64(flags),
			Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
		})
		if err != unix.ENOSYS && err != unix.EPERM {
			return fd, err
		}
	}
	return resolveByComponents(r.fd, path, followLast)
}

// resolveByComponents is the resolver for kernels without openat2.
func resolveByComponents(rootFd int, path string, followLast bool) (int, error) {
	dup := func() (int, error) { return unix.FcntlInt(uintptr(rootFd), unix.F_DUPFD_CLOEXEC, 0) }
	cur, err := dup()
	if err != nil {
		return -1, err
	}
	var parents []int // ancestors of cur, outermost first
	release := func() {
		for _, fd := range parents {
			unix.Close(fd)
		}
		parents = nil
	}
	fail := func(err error) (int, error) {
		release()
		unix.Close(cur)
		return -1, err
	}
	links := 0
	remaining := path
	for remaining != "" {
		if remaining[0] == '/' {
			// An absolute path or link target restarts at the root.
			release()
			unix.Close(cur)
			if cur, err = dup(); err != nil {
				return -1, err
			}
			remaining = strings.TrimLeft(remaining, "/")
			continue
		}
		name, rest, _ := strings.Cut(remaining, "/")
		remaining = strings.TrimLeft(rest, "/")
		switch name {
		case ".":
			continue
		case "..":
			// The root is its own parent.
			if n := len(parents); n > 0 {
				unix.Close(cur)
				cur, parents = parents[n-1], parents[:n-1]
			}
			continue
		}
		last := remaining == ""
		fd, err := unix.Openat(cur, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fail(err)
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			unix.Close(fd)
			return fail(err)
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			parents = append(parents, cur)
			cur = fd
		case unix.S_IFLNK:
			if last && !followLast {
				// The caller decides what a link at the end means.
				release()
				unix.Close(cur)
				return fd, nil
			}
			links++
			buf := make([]byte, maxPath+1)
			n, err := unix.Readlinkat(fd, "", buf)
			unix.Close(fd)
			if err != nil {
				return fail(err)
			}
			if links > maxLinks {
				return fail(unix.ELOOP)
			}
			if n == 0 || n > maxPath || len(remaining)+n+1 > maxPath*16 {
				return fail(unix.ENAMETOOLONG)
			}
			remaining = string(buf[:n]) + "/" + remaining
		default:
			if last {
				release()
				unix.Close(cur)
				return fd, nil
			}
			unix.Close(fd)
			return fail(unix.ENOTDIR)
		}
	}
	release()
	return cur, nil
}

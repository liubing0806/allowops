package jvmtarget

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func (l *layout) openRoot() *Root {
	l.t.Helper()
	r, err := OpenRoot(l.root)
	if err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() { r.Close() })
	return r
}

func ownIDs() (uint32, uint32) { return uint32(os.Getuid()), uint32(os.Getgid()) }

func TestCreateMakesAnOwnedEmptyFileAndRemoveDeletesIt(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		r := l.openRoot()
		uid, gid := ownIDs()
		for _, dir := range []string{"/tmp", "tmp", "/tmp/../tmp"} {
			f, err := r.Create(dir, ".attach_pid7", 0o600, uid, gid)
			if err != nil {
				t.Fatalf("%q: %v", dir, err)
			}
			path := filepath.Join(l.root, "tmp", ".attach_pid7")
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			st := info.Sys().(*syscall.Stat_t)
			if !info.Mode().IsRegular() || info.Size() != 0 || info.Mode().Perm() != 0o600 || st.Uid != uid || st.Gid != gid {
				t.Errorf("file = %v size %d uid %d gid %d", info.Mode(), info.Size(), st.Uid, st.Gid)
			}
			if f.Path == "" {
				t.Error("no path for messages")
			}
			if err := f.Remove(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("file still there: %v", err)
			}
			if err := f.Remove(); err != nil {
				t.Errorf("second Remove: %v", err)
			}
		}
	})
}

func TestCreateInTheRootDirectory(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		r := l.openRoot()
		uid, gid := ownIDs()
		f, err := r.Create("/", ".attach_pid1", 0o600, uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(filepath.Join(l.root, ".attach_pid1")); err != nil {
			t.Error(err)
		}
		if err := f.Remove(); err != nil {
			t.Fatal(err)
		}
	})
}

// The name exists: nothing is opened, followed or changed.
func TestCreateRefusesAnExistingName(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		r := l.openRoot()
		uid, gid := ownIDs()
		writeFile(t, filepath.Join(l.root, "tmp", ".attach_pid7"), "previous")
		if _, err := r.Create("/tmp", ".attach_pid7", 0o600, uid, gid); !errors.Is(err, unix.EEXIST) {
			t.Errorf("existing file: %v; want EEXIST", err)
		}
		if got, _ := os.ReadFile(filepath.Join(l.root, "tmp", ".attach_pid7")); string(got) != "previous" {
			t.Errorf("the existing file changed: %q", got)
		}
		// A link at the name, to a file outside the container or to nothing, is not followed either.
		target := filepath.Join(l.outside, "victim")
		writeFile(t, target, "host-file")
		for name, to := range map[string]string{".attach_pid8": target, ".attach_pid9": filepath.Join(l.outside, "new")} {
			if err := os.Symlink(to, filepath.Join(l.root, "tmp", name)); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Create("/tmp", name, 0o600, uid, gid); !errors.Is(err, unix.EEXIST) {
				t.Errorf("%s: %v; want EEXIST", name, err)
			}
		}
		if got, _ := os.ReadFile(target); string(got) != "host-file" {
			t.Errorf("the host file changed: %q", got)
		}
		if _, err := os.Lstat(filepath.Join(l.outside, "new")); err == nil {
			t.Error("a file was created through the link")
		}
	})
}

// A container that makes its directory a link to a host path does not get the file there.
func TestCreateDoesNotFollowLinksOutOfTheRoot(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		r := l.openRoot()
		uid, gid := ownIDs()
		if err := os.RemoveAll(filepath.Join(l.root, "tmp")); err != nil {
			t.Fatal(err)
		}
		for _, target := range []string{l.outside, "../outside"} {
			l.link(target, "tmp")
			// Control: a plain creation through the link reaches the host directory.
			control := filepath.Join(l.root, "tmp", "control")
			writeFile(t, control, "x")
			if _, err := os.Stat(filepath.Join(l.outside, "control")); err != nil {
				t.Fatalf("control: the link does not lead to the host directory: %v", err)
			}
			os.Remove(control)
			if f, err := r.Create("/tmp", ".attach_pid7", 0o600, uid, gid); err == nil {
				f.Remove()
				t.Errorf("%s: created in the host directory", target)
			}
			if _, err := os.Lstat(filepath.Join(l.outside, ".attach_pid7")); err == nil {
				t.Errorf("%s: the file exists in the host directory", target)
			}
		}
	})
}

func TestCreateFollowsALinkInsideTheRoot(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		r := l.openRoot()
		uid, gid := ownIDs()
		if err := os.MkdirAll(filepath.Join(l.root, "var", "tmp"), 0o755); err != nil {
			t.Fatal(err)
		}
		l.link("/var/tmp", "tmp2")
		f, err := r.Create("/tmp2", ".attach_pid7", 0o600, uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Remove()
		if _, err := os.Lstat(filepath.Join(l.root, "var", "tmp", ".attach_pid7")); err != nil {
			t.Error(err)
		}
	})
}

// Remove acts on the directory the file was made in, also when the path leads elsewhere by then.
func TestRemoveDeletesInTheOriginalDirectory(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		r := l.openRoot()
		uid, gid := ownIDs()
		f, err := r.Create("/tmp", ".attach_pid7", 0o600, uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		bystander := filepath.Join(l.outside, ".attach_pid7")
		writeFile(t, bystander, "host-file")
		moved := filepath.Join(l.base, "moved")
		if err := os.Rename(filepath.Join(l.root, "tmp"), moved); err != nil {
			t.Fatal(err)
		}
		l.link(l.outside, "tmp")
		if err := f.Remove(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(filepath.Join(moved, ".attach_pid7")); err == nil {
			t.Error("the file is still in the directory it was made in")
		}
		if got, err := os.ReadFile(bystander); err != nil || string(got) != "host-file" {
			t.Errorf("the host file: %q, %v", got, err)
		}
	})
}

func TestRemoveOfAFileThatIsGone(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		r := l.openRoot()
		uid, gid := ownIDs()
		f, err := r.Create("/tmp", ".attach_pid7", 0o600, uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(l.root, "tmp", ".attach_pid7")); err != nil {
			t.Fatal(err)
		}
		if err := f.Remove(); err != nil {
			t.Errorf("Remove of a file that is gone: %v", err)
		}
		var nilFile *CreatedFile
		if err := nilFile.Remove(); err != nil {
			t.Errorf("Remove on nil: %v", err)
		}
	})
}

func TestCreateRejectsBadArguments(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		r := l.openRoot()
		uid, gid := ownIDs()
		writeFile(t, filepath.Join(l.root, "tmp", "plain"), "x")
		for _, c := range []struct{ dir, name string }{
			{"/tmp", ""}, {"/tmp", "."}, {"/tmp", ".."}, {"/tmp", "a/b"}, {"/tmp", "a\x00b"}, {"/tmp", string(make([]byte, 300))},
			{"", "x"}, {"/tmp/", "x"}, {"/tmp\x00", "x"}, {"/missing", "x"}, {"/tmp/plain", "x"},
		} {
			if f, err := r.Create(c.dir, c.name, 0o600, uid, gid); err == nil {
				f.Remove()
				t.Errorf("Create(%q, %q) succeeded", c.dir, c.name)
			}
		}
	})
}

func TestCreateInAnUnwritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		r := l.openRoot()
		uid, gid := ownIDs()
		dir := filepath.Join(l.root, "ro")
		if err := os.Mkdir(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Create("/ro", ".attach_pid7", 0o600, uid, gid); !errors.Is(err, unix.EACCES) {
			t.Errorf("err = %v; want EACCES", err)
		}
	})
}

// A file that cannot be given to the target is not left behind.
func TestCreateRemovesTheFileWhenChownFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may give files away")
	}
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		r := l.openRoot()
		uid, gid := ownIDs()
		if _, err := r.Create("/tmp", ".attach_pid7", 0o600, uid+1, gid); !errors.Is(err, unix.EPERM) {
			t.Errorf("err = %v; want EPERM", err)
		}
		if _, err := os.Lstat(filepath.Join(l.root, "tmp", ".attach_pid7")); err == nil {
			t.Error("the file was left behind")
		}
	})
}

func TestStat(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		r := l.openRoot()
		l.link("/tmp", "tmp2")
		st, err := r.Stat("/tmp2", false)
		if err != nil || st.Mode&unix.S_IFMT != unix.S_IFLNK {
			t.Errorf("no follow: mode %o, %v; want a link", st.Mode, err)
		}
		st, err = r.Stat("/tmp2", true)
		if err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
			t.Errorf("follow: mode %o, %v; want a directory", st.Mode, err)
		}
		// A link out of the container is resolved inside it.
		l.link(l.outside, "out")
		if _, err := r.Stat("/out/hsperfdata_x/1", true); err == nil {
			t.Error("a path through a link to the host was found")
		}
		if _, err := r.Stat("/tmp/missing", false); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("missing: %v", err)
		}
		for _, path := range []string{"", "/tmp/", "/tmp\x00x"} {
			if _, err := r.Stat(path, true); err == nil {
				t.Errorf("Stat(%q) succeeded", path)
			}
		}
	})
}

// listenUnix makes a socket file the way HotSpot's attach listener does.
func listenUnix(t *testing.T, path string) *net.UnixListener {
	t.Helper()
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestOpenSocket(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		r := l.openRoot()
		uid, _ := ownIDs()
		listenUnix(t, filepath.Join(l.root, "tmp", ".java_pid7"))
		fd, err := r.OpenSocket("/tmp/.java_pid7", uid)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
			t.Errorf("fstat: mode %o, %v", st.Mode, err)
		}
		// The descriptor reaches the socket, as the path /proc/self/fd/<fd> does for connect.
		conn, err := net.Dial("unix", "/proc/self/fd/"+strconv.Itoa(fd))
		if err != nil {
			t.Fatalf("connect through the descriptor: %v", err)
		}
		conn.Close()
	})
}

func TestOpenSocketRejectsEverythingElse(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		r := l.openRoot()
		uid, _ := ownIDs()
		tmp := filepath.Join(l.root, "tmp")
		listenUnix(t, filepath.Join(tmp, "real"))
		hostSocket := filepath.Join(l.outside, "host.sock")
		hostListener := listenUnix(t, hostSocket)
		accepted := make(chan struct{}, 4)
		go func() {
			for {
				c, err := hostListener.Accept()
				if err != nil {
					return
				}
				c.Close()
				accepted <- struct{}{}
			}
		}()
		writeFile(t, filepath.Join(tmp, "file"), "x")
		if err := os.Mkdir(filepath.Join(tmp, "dir"), 0o755); err != nil {
			t.Fatal(err)
		}
		for name, target := range map[string]string{
			"link-inside": "real",
			"link-host":   hostSocket,
			"link-rel":    "../../outside/host.sock",
			"dangling":    "missing",
		} {
			if err := os.Symlink(target, filepath.Join(tmp, name)); err != nil {
				t.Fatal(err)
			}
		}
		for name, want := range map[string]error{
			"file":        ErrNotSocket,
			"dir":         ErrNotSocket,
			"link-inside": ErrSymlink,
			"link-host":   ErrSymlink,
			"link-rel":    ErrSymlink,
			"dangling":    ErrSymlink,
			"missing":     os.ErrNotExist,
		} {
			fd, err := r.OpenSocket("/tmp/"+name, uid)
			if err == nil {
				unix.Close(fd)
			}
			if !errors.Is(err, want) {
				t.Errorf("%s: err = %v; want %v", name, err, want)
			}
		}
		if fd, err := r.OpenSocket("/tmp/real", uid+1); !errors.Is(err, errForeignOwner) {
			if err == nil {
				unix.Close(fd)
			}
			t.Errorf("another owner: %v; want errForeignOwner", err)
		}
		for _, path := range []string{"", "/tmp/", "/tmp/real\x00"} {
			if fd, err := r.OpenSocket(path, uid); err == nil {
				unix.Close(fd)
				t.Errorf("OpenSocket(%q) succeeded", path)
			}
		}
		select {
		case <-accepted:
			t.Error("the host socket got a connection")
		default:
		}
	})
}

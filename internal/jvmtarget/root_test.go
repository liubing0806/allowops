package jvmtarget

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Each test runs twice: with openat2 where the kernel has it, and with the
// component-wise resolver used on kernels before 5.6.
func eachResolver(t *testing.T, test func(t *testing.T)) {
	t.Helper()
	for _, mode := range []struct {
		name     string
		fallback bool
	}{{"openat2", false}, {"fallback", true}} {
		t.Run(mode.name, func(t *testing.T) {
			if !mode.fallback && !openat2Available() {
				t.Skip("kernel without openat2")
			}
			previous := forceFallback
			forceFallback = mode.fallback
			defer func() { forceFallback = previous }()
			test(t)
		})
	}
}

// layout is a fake container root next to a host directory holding a secret.
type layout struct {
	t       *testing.T
	base    string
	root    string // the container's root
	outside string // a host directory the container must not reach
}

const hostSecret = "HOST-SECRET"

func newLayout(t *testing.T) *layout {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	l := &layout{t: t, base: base, root: filepath.Join(base, "root"), outside: filepath.Join(base, "outside")}
	for _, dir := range []string{l.root, filepath.Join(l.outside, "hsperfdata_x"), filepath.Join(l.root, "tmp", "hsperfdata_x")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(l.outside, "hsperfdata_x", "1"), hostSecret)
	writeFile(t, filepath.Join(l.root, "tmp", "hsperfdata_x", "1"), "container")
	return l
}

// read may run in a goroutine, so it returns errors instead of failing the test.
func (l *layout) read(path string) (string, error) {
	r, err := OpenRoot(l.root)
	if err != nil {
		return "", err
	}
	defer r.Close()
	f, err := r.OpenFile(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (l *layout) link(target, name string) {
	l.t.Helper()
	path := filepath.Join(l.root, name)
	_ = os.Remove(path)
	if err := os.Symlink(target, path); err != nil {
		l.t.Fatal(err)
	}
}

func TestOpenFileReadsContainerFile(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		for _, path := range []string{"/tmp/hsperfdata_x/1", "tmp/hsperfdata_x/1", "//tmp///hsperfdata_x/./1", "/tmp/../tmp/hsperfdata_x/1"} {
			got, err := l.read(path)
			if err != nil || got != "container" {
				t.Errorf("%q: %q, %v", path, got, err)
			}
		}
	})
}

// The root itself may be a symbolic link, as /proc/<pid>/root is.
func TestOpenRootThroughSymlink(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		link := filepath.Join(l.base, "rootlink")
		if err := os.Symlink(l.root, link); err != nil {
			t.Fatal(err)
		}
		r, err := OpenRoot(link)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		f, err := r.OpenFile("/tmp/hsperfdata_x/1")
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		if _, err := OpenRoot(filepath.Join(l.root, "tmp", "hsperfdata_x", "1")); err == nil {
			t.Error("a regular file was accepted as a root")
		}
		if _, err := OpenRoot(filepath.Join(l.base, "missing")); err == nil {
			t.Error("a missing directory was accepted as a root")
		}
	})
}

// A symbolic link inside the container that points to a host path must not be
// followed to the host. The control shows that following it naively would read
// the host file, so the test would catch a regression.
func TestOpenFileDoesNotFollowAbsoluteSymlinkToHost(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		if err := os.RemoveAll(filepath.Join(l.root, "tmp")); err != nil {
			t.Fatal(err)
		}
		l.link(l.outside, "tmp")
		naive, err := os.ReadFile(filepath.Join(l.root, "tmp", "hsperfdata_x", "1"))
		if err != nil || string(naive) != hostSecret {
			t.Fatalf("control failed: %q, %v", naive, err)
		}
		got, err := l.read("/tmp/hsperfdata_x/1")
		if err == nil || strings.Contains(got, hostSecret) {
			t.Fatalf("read %q, %v; want an error", got, err)
		}
	})
}

func TestOpenFileDoesNotFollowRelativeSymlinkOutOfRoot(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		if err := os.RemoveAll(filepath.Join(l.root, "tmp")); err != nil {
			t.Fatal(err)
		}
		// root/tmp -> ../outside leaves the container root.
		l.link("../outside", "tmp")
		naive, err := os.ReadFile(filepath.Join(l.root, "tmp", "hsperfdata_x", "1"))
		if err != nil || string(naive) != hostSecret {
			t.Fatalf("control failed: %q, %v", naive, err)
		}
		got, err := l.read("/tmp/hsperfdata_x/1")
		if err == nil || strings.Contains(got, hostSecret) {
			t.Fatalf("read %q, %v; want an error", got, err)
		}
	})
}

// ".." at the container root stays at the container root.
func TestOpenFileClampsDotDotAtRoot(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		writeFile(t, filepath.Join(l.root, "etc", "marker"), "container-etc")
		writeFile(t, filepath.Join(l.base, "etc", "marker"), "host-etc")
		got, err := l.read("/../../../etc/marker")
		if err != nil || got != "container-etc" {
			t.Errorf("read %q, %v", got, err)
		}
		got, err = l.read("/tmp/../../../../etc/marker")
		if err != nil || got != "container-etc" {
			t.Errorf("read %q, %v", got, err)
		}
	})
}

// Symbolic links that stay inside the container are fine: /tmp is often one.
func TestOpenFileFollowsSymlinksInsideRoot(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		writeFile(t, filepath.Join(l.root, "var", "tmp", "hsperfdata_y", "7"), "var-tmp")
		l.link("var/tmp", "tmp2")
		l.link("/var/tmp", "tmp3")
		l.link("../var/tmp", "tmp4")
		l.link("tmp3", "tmp5")
		// An absolute link in a subdirectory resolves against the container root.
		if err := os.MkdirAll(filepath.Join(l.root, "run"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/var/tmp", filepath.Join(l.root, "run", "tmp")); err != nil {
			t.Fatal(err)
		}
		for _, dir := range []string{"tmp2", "tmp3", "tmp4", "tmp5", "run/tmp"} {
			got, err := l.read("/" + dir + "/hsperfdata_y/7")
			if err != nil || got != "var-tmp" {
				t.Errorf("%s: %q, %v", dir, got, err)
			}
		}
	})
}

func TestOpenFileRejectsFinalSymlink(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		dir := filepath.Join(l.root, "tmp", "hsperfdata_x")
		for name, target := range map[string]string{
			"abs-host":   filepath.Join(l.outside, "hsperfdata_x", "1"),
			"rel-host":   "../../../outside/hsperfdata_x/1",
			"inside":     "1",
			"inside-abs": "/tmp/hsperfdata_x/1",
			"dangling":   "missing",
		} {
			if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			got, err := l.read("/tmp/hsperfdata_x/" + name)
			if !errors.Is(err, ErrSymlink) || got != "" {
				t.Errorf("%s: %q, %v; want ErrSymlink", name, got, err)
			}
		}
	})
}

func TestOpenFileRejectsSpecialFiles(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		dir := filepath.Join(l.root, "tmp", "hsperfdata_x")
		if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, "dir"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"fifo", "dir"} {
			done := make(chan error, 1)
			go func() {
				_, err := l.read("/tmp/hsperfdata_x/" + name)
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, ErrNotRegular) {
					t.Errorf("%s: err = %v; want ErrNotRegular", name, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s: opening blocked", name)
			}
		}
		// A character device: opening it must not even be attempted.
		dev, err := OpenRoot("/dev")
		if err != nil {
			t.Fatal(err)
		}
		defer dev.Close()
		if f, err := dev.OpenFile("/null"); !errors.Is(err, ErrNotRegular) {
			if f != nil {
				f.Close()
			}
			t.Errorf("/dev/null: err = %v; want ErrNotRegular", err)
		}
	})
}

func TestOpenFileRejectsLoopsAndBadPaths(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		l.link("b", "a")
		l.link("a", "b")
		if _, err := l.read("/a/x"); err == nil {
			t.Error("a symlink loop was followed")
		}
		// A chain longer than the kernel's limit of 40 links.
		previous := "tmp"
		for i := 0; i < 50; i++ {
			name := "chain" + string(rune('A'+i/26)) + string(rune('a'+i%26))
			l.link(previous, name)
			previous = name
		}
		if _, err := l.read("/" + previous + "/hsperfdata_x/1"); err == nil {
			t.Error("a chain of 50 symlinks was followed")
		}
		for _, path := range []string{"", "/tmp/hsperfdata_x/1\x00", "/tmp/hsperfdata_x/missing", "/tmp/hsperfdata_x/1/"} {
			if got, err := l.read(path); err == nil {
				t.Errorf("%q read %q", path, got)
			}
		}
		if _, err := l.read("/tmp/hsperfdata_x/1/extra"); err == nil {
			t.Error("a path below a regular file resolved")
		}
	})
}

func TestOpenDirListsNames(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		writeFile(t, filepath.Join(l.root, "tmp", "other"), "x")
		r, err := OpenRoot(l.root)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		d, err := r.OpenDir("/tmp")
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		names, err := d.Readdirnames(-1)
		if err != nil || len(names) != 2 {
			t.Errorf("names = %v, %v", names, err)
		}
		if f, err := r.OpenDir("/tmp/hsperfdata_x/1"); err == nil {
			f.Close()
			t.Error("a regular file opened as a directory")
		}
		// A symlinked directory in the middle follows inside the root only.
		if err := os.RemoveAll(filepath.Join(l.root, "tmp")); err != nil {
			t.Fatal(err)
		}
		l.link(l.outside, "tmp")
		if f, err := r.OpenDir("/tmp"); err == nil {
			f.Close()
			t.Error("a symlink to a host directory opened")
		}
	})
}

// While the resolver walks the path, a process in the container swaps a
// directory with a symbolic link to the host. No interleaving may reach the host file.
func TestOpenFileSurvivesConcurrentSwaps(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		real := filepath.Join(l.root, "tmp")
		spare := filepath.Join(l.root, "tmp.real")
		if err := os.Rename(real, spare); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(l.root, "tmp.link")
		if err := os.Symlink(l.outside, link); err != nil {
			t.Fatal(err)
		}
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// tmp alternates between the real directory and the host symlink.
				_ = os.Rename(spare, real)
				_ = os.Rename(real, spare)
				_ = os.Rename(link, real)
				_ = os.Rename(real, link)
			}
		}()
		defer func() { close(stop); wg.Wait() }()
		for i := 0; i < 3000; i++ {
			if got, _ := l.read("/tmp/hsperfdata_x/1"); strings.Contains(got, hostSecret) {
				t.Fatalf("iteration %d read the host file", i)
			}
		}
	})
}

// A container can make /tmp a link to another directory of its own (for example /var/tmp/x).
// OpenDir follows it inside the root, like a link in the middle of a path.
func TestOpenDirFollowsFinalSymlinkInsideRoot(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		for name, target := range map[string]string{"absolute": "/var/tmp/x", "relative": "../var/tmp/x", "chain": "/var/tmp/hop"} {
			t.Run(name, func(t *testing.T) {
				l := newLayout(t)
				if err := os.RemoveAll(filepath.Join(l.root, "tmp")); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(l.root, "var", "tmp", "x", "hsperfdata_x"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("x", filepath.Join(l.root, "var", "tmp", "hop")); err != nil {
					t.Fatal(err)
				}
				l.link(target, "tmp")
				r, err := OpenRoot(l.root)
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				d, err := r.OpenDir("/tmp")
				if err != nil {
					t.Fatalf("OpenDir through a link inside the root: %v", err)
				}
				defer d.Close()
				if names, err := d.Readdirnames(-1); err != nil || len(names) != 1 || names[0] != "hsperfdata_x" {
					t.Errorf("names = %v, %v", names, err)
				}
			})
		}
	})
}

// A link to a host path is resolved from the container's root: it reaches the
// container's directory of that name, or nothing, and never the host's.
func TestOpenDirResolvesHostPathLinkInsideRoot(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		l.link(l.outside, "alias")
		r, err := OpenRoot(l.root)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if d, err := r.OpenDir("/alias"); err == nil {
			d.Close()
			t.Fatal("the link to a host path opened although the container has no such directory")
		}
		// The container has a directory at the same path; that one is listed.
		if err := os.MkdirAll(filepath.Join(l.root, l.outside, "in-root"), 0o755); err != nil {
			t.Fatal(err)
		}
		d, err := r.OpenDir("/alias")
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		if names, err := d.Readdirnames(-1); err != nil || len(names) != 1 || names[0] != "in-root" {
			t.Errorf("names = %v, %v; want only the container's own directory", names, err)
		}
	})
}

func TestOpenDirRejectsLinkLoops(t *testing.T) {
	eachResolver(t, func(t *testing.T) {
		l := newLayout(t)
		l.link("/b", "a")
		l.link("/a", "b")
		r, err := OpenRoot(l.root)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if d, err := r.OpenDir("/a"); err == nil {
			d.Close()
			t.Error("a link loop opened")
		} else if !errors.Is(err, syscall.ELOOP) {
			t.Errorf("err = %v; want ELOOP", err)
		}
	})
}

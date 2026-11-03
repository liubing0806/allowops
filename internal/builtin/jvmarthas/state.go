package jvmarthas

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// StateDirectory holds the lock files, the session records and the attach
// counters. It belongs to root and has mode 0700.
const StateDirectory = "/var/lib/allowops-exec/arthas"

// ErrBusy means another call holds the lock of the JVM.
var ErrBusy = errors.New("another jvm_arthas call is using this JVM")

const (
	recordVersion = 1
	// maxStateFile bounds what is read from a record or a counter.
	maxStateFile = 64 << 10
	// maxStateEntries bounds the names read from the directory.
	maxStateEntries = 1 << 16

	extLock    = ".lock"
	extSession = ".session"
	extCount   = ".count"
)

// Key identifies one process of one boot of the host. A pid that is reused
// has another start time, and a host that rebooted has another boot id.
type Key struct {
	BootID    string
	PID       int
	StartTime uint64
}

var (
	bootIDPattern = regexp.MustCompile(`^[0-9a-f-]{1,64}$`)
	// stateName splits <boot id>-<pid>-<start time>.<extension>; the boot id holds dashes itself.
	stateName = regexp.MustCompile(`^([0-9a-f-]{1,64})-([0-9]{1,10})-([0-9]{1,20})(\.lock|\.session|\.count)$`)
)

// String is the common part of the names of the files that belong to the process.
func (k Key) String() string {
	return k.BootID + "-" + strconv.Itoa(k.PID) + "-" + strconv.FormatUint(k.StartTime, 10)
}

func (k Key) validate() error {
	if !bootIDPattern.MatchString(k.BootID) || k.PID <= 0 {
		return fmt.Errorf("invalid process key %q", k.String())
	}
	return nil
}

// State is the directory of the records. A State is safe for concurrent use by
// several goroutines; the locks are held per Lock value.
type State struct {
	dir   *os.File
	owner uint32
}

// Lock is the exclusive lock of one JVM. It is released by Unlock, or when the
// process ends.
type Lock struct {
	Key  Key
	file *os.File
}

// Record describes one open Arthas session. It is written before the attach and
// removed after the clean-up was confirmed, so a record that outlives its call
// marks a session that may still be running.
type Record struct {
	Version   int       `json:"version"`
	BootID    string    `json:"boot_id"`
	PID       int       `json:"pid"`
	StartTime uint64    `json:"start_time"`
	Target    string    `json:"target"`
	Command   string    `json:"command"`
	Port      int       `json:"port"`
	Password  string    `json:"password"`
	SessionID string    `json:"session_id,omitempty"`
	Created   time.Time `json:"created"`
	// Deadline is when Arthas drops the idle session by itself (sessionTimeout).
	Deadline time.Time `json:"deadline"`
	// LoadUnanswered is set from before the load command is sent until the JVM answers it. Until
	// the deadline the server may still start, so a missing server does not make the record stale.
	LoadUnanswered bool `json:"load_unanswered,omitempty"`
}

// Counter is what the state directory remembers of the attaches to one JVM.
type Counter struct {
	Attaches   int       `json:"attaches"`
	LastAttach time.Time `json:"last_attach"`
	// GCCount is the sum of the collector invocations that hsperfdata showed before the last attach.
	GCCount int64 `json:"gc_count"`
	// AttachesSinceGC is the number of the latest attaches that saw GCCount, the attaches since the
	// count last changed. It is zero in a counter written before the field existed.
	AttachesSinceGC int `json:"attaches_since_gc"`
}

// unseenAttaches returns the attaches whose metaspace hsperfdata may not show yet: no collection
// happened since them, and sun.gc.metaspace.used changes at a collection only.
func (c Counter) unseenAttaches(gcCount int64) int {
	if gcCount != c.GCCount {
		return 0
	}
	return c.AttachesSinceGC
}

// OpenState opens the state directory, creating it with mode 0700 when it is missing.
// The directory must belong to the user owner and have mode 0700, and no component of
// the path may be a symbolic link.
func OpenState(path string, owner uint32) (*State, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("state directory %q must be a clean absolute path", path)
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) {
			if mkErr := unix.Mkdirat(fd, part, 0o700); mkErr != nil && !errors.Is(mkErr, unix.EEXIST) {
				unix.Close(fd)
				return nil, fmt.Errorf("creating %s: %w", path, mkErr)
			}
			next, err = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		unix.Close(fd)
		if err != nil {
			return nil, fmt.Errorf("opening %s: %w", path, err)
		}
		fd = next
	}
	dir := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		dir.Close()
		return nil, err
	}
	if st.Uid != owner || st.Mode&0o7777 != 0o700 {
		dir.Close()
		return nil, fmt.Errorf("state directory %s must belong to uid %d and have mode 0700 (uid %d, mode %04o)", path, owner, st.Uid, st.Mode&0o7777)
	}
	return &State{dir: dir, owner: owner}, nil
}

// Close releases the directory.
func (s *State) Close() error { return s.dir.Close() }

// openFile opens a regular file of the directory that belongs to the owner. The name never
// leaves the directory and a symbolic link at the end is not followed.
func (s *State) openFile(name string, flags int, perm uint32) (*os.File, error) {
	fd, err := unix.Openat(int(s.dir.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, perm)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != s.owner || st.Mode&0o7777 != 0o600 || st.Nlink != 1 {
		f.Close()
		return nil, fmt.Errorf("%s is not a private regular file of uid %d (mode %04o, links %d)", name, s.owner, st.Mode&0o7777, st.Nlink)
	}
	return f, nil
}

// TryLock takes the lock of the JVM without waiting; it fails with ErrBusy when another holds it.
func (s *State) TryLock(k Key) (*Lock, error) {
	if err := k.validate(); err != nil {
		return nil, err
	}
	f, err := s.openFile(k.String()+extLock, unix.O_RDWR|unix.O_CREAT, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w (%s)", ErrBusy, k)
		}
		return nil, err
	}
	return &Lock{Key: k, file: f}, nil
}

// Unlock releases the lock. The lock file stays; removing it would let two callers lock two files of one name.
func (l *Lock) Unlock() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := l.file.Close() // closing the descriptor releases the flock
	l.file = nil
	return err
}

// Key returns the key of the record.
func (r Record) Key() Key { return Key{BootID: r.BootID, PID: r.PID, StartTime: r.StartTime} }

// Expired reports whether Arthas has dropped the session by now.
func (r Record) Expired(now time.Time) bool { return !now.Before(r.Deadline) }

// writeFile replaces name atomically: a private temporary file in the directory is
// renamed over it. The old file is never opened, so a link at the name cannot redirect the write.
func (s *State) writeFile(name string, data []byte) error {
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	tmp := ".write-" + hex.EncodeToString(random[:])
	fd, err := unix.Openat(int(s.dir.Fd()), tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return &os.PathError{Op: "create", Path: tmp, Err: err}
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(int(s.dir.Fd()), tmp, int(s.dir.Fd()), name)
	}
	if err != nil {
		unix.Unlinkat(int(s.dir.Fd()), tmp, 0)
		return fmt.Errorf("writing %s: %w", name, err)
	}
	return s.dir.Sync()
}

func (s *State) readFile(name string) ([]byte, error) {
	f, err := s.openFile(name, unix.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStateFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxStateFile {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, maxStateFile)
	}
	return data, nil
}

func (s *State) remove(name string) error {
	if err := unix.Unlinkat(int(s.dir.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return &os.PathError{Op: "remove", Path: name, Err: err}
	}
	return nil
}

// WriteRecord stores the record, replacing the previous one of the same JVM, with mode 0600.
func (s *State) WriteRecord(r Record) error {
	if err := r.Key().validate(); err != nil {
		return err
	}
	r.Version = recordVersion
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return s.writeFile(r.Key().String()+extSession, data)
}

// ReadRecord returns the record of the JVM; the error matches fs.ErrNotExist when there is none.
func (s *State) ReadRecord(k Key) (Record, error) {
	var r Record
	if err := k.validate(); err != nil {
		return r, err
	}
	data, err := s.readFile(k.String() + extSession)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return Record{}, fmt.Errorf("record %s: %w", k, err)
	}
	if r.Version != recordVersion || r.Key() != k {
		return Record{}, fmt.Errorf("record %s does not describe this process", k)
	}
	return r, nil
}

// RemoveRecord deletes the record; a missing record is not an error.
func (s *State) RemoveRecord(k Key) error {
	if err := k.validate(); err != nil {
		return err
	}
	return s.remove(k.String() + extSession)
}

// names lists the files of the directory that belong to a process, as key and extension.
func (s *State) names() (map[Key][]string, []Key, error) {
	// A new open file description starts at the first entry; a duplicate would share the position
	// with the earlier listings.
	fd, err := unix.Openat(int(s.dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	dir := os.NewFile(uintptr(fd), s.dir.Name())
	defer dir.Close()
	all, err := dir.Readdirnames(maxStateEntries)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, err
	}
	slices.Sort(all)
	byKey := map[Key][]string{}
	var order []Key
	for _, name := range all {
		m := stateName.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		pid, err1 := strconv.Atoi(m[2])
		start, err2 := strconv.ParseUint(m[3], 10, 64)
		if err1 != nil || err2 != nil || pid <= 0 {
			continue
		}
		k := Key{BootID: m[1], PID: pid, StartTime: start}
		if _, seen := byKey[k]; !seen {
			order = append(order, k)
		}
		byKey[k] = append(byKey[k], m[4])
	}
	return byKey, order, nil
}

// Records lists the keys of the stored records in a fixed order.
func (s *State) Records() ([]Key, error) {
	byKey, order, err := s.names()
	if err != nil {
		return nil, err
	}
	var keys []Key
	for _, k := range order {
		if slices.Contains(byKey[k], extSession) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// Counter returns the attach counter of the JVM; the zero value when there is none.
func (s *State) Counter(k Key) (Counter, error) {
	var c Counter
	if err := k.validate(); err != nil {
		return c, err
	}
	data, err := s.readFile(k.String() + extCount)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil || c.Attaches < 0 || c.AttachesSinceGC < 0 || c.AttachesSinceGC > c.Attaches {
		return Counter{}, fmt.Errorf("counter %s is damaged", k)
	}
	return c, nil
}

// AddAttach counts one attach at the given time, with the sum of the collector invocations
// that hsperfdata showed before it, and returns the new counter.
func (s *State) AddAttach(k Key, at time.Time, gcCount int64) (Counter, error) {
	c, err := s.Counter(k)
	if err != nil {
		return c, err
	}
	if gcCount != c.GCCount {
		c.AttachesSinceGC = 0
	}
	c.Attaches++
	c.AttachesSinceGC++
	c.GCCount = gcCount
	c.LastAttach = at.UTC()
	data, err := json.Marshal(c)
	if err != nil {
		return c, err
	}
	return c, s.writeFile(k.String()+extCount, data)
}

// Prune removes the counters and the lock files of processes for which alive reports false,
// unless their lock is held or they still have a record. It returns the number of removed files.
func (s *State) Prune(alive func(Key) bool) (int, error) {
	byKey, order, err := s.names()
	if err != nil {
		return 0, err
	}
	removed := 0
	var errs []error
	for _, k := range order {
		files := byKey[k]
		if slices.Contains(files, extSession) || alive(k) {
			continue
		}
		lock, err := s.TryLock(k)
		if err != nil {
			if !errors.Is(err, ErrBusy) {
				errs = append(errs, err)
			}
			continue
		}
		// TryLock made the lock file if it was missing, so it is removed in every case.
		for _, ext := range []string{extCount, extLock} {
			if err := s.remove(k.String() + ext); err != nil {
				errs = append(errs, err)
				continue
			}
			if slices.Contains(files, ext) {
				removed++
			}
		}
		lock.Unlock()
	}
	return removed, errors.Join(errs...)
}

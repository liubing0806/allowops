package jvmarthas

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func openTestState(t *testing.T) (*State, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "arthas")
	s, err := OpenState(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

var testKey = Key{BootID: "0123abcd-0000-4000-8000-123456789abc", PID: 4242, StartTime: 777}

func testRecord() Record {
	return Record{
		Version: 1, BootID: testKey.BootID, PID: testKey.PID, StartTime: testKey.StartTime,
		Target: "api", Command: "dashboard", Port: 18570, Password: "abcdefghijklmnopqrstuvwxyz012345",
		SessionID: "sid-1", Created: time.Unix(1_700_000_000, 0).UTC(), Deadline: time.Unix(1_700_000_030, 0).UTC(),
	}
}

func TestOpenStateCreatesAPrivateDirectory(t *testing.T) {
	_, path := openTestState(t)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Errorf("state directory mode = %v", info.Mode())
	}
}

func TestOpenStateRefusesUnsafeDirectories(t *testing.T) {
	base := t.TempDir()
	loose := filepath.Join(base, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenState(loose, uint32(os.Getuid())); err == nil {
		t.Error("a directory with mode 0755 was accepted")
	}
	private := filepath.Join(base, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenState(private, uint32(os.Getuid())+1); err == nil {
		t.Error("a directory of another user was accepted")
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenState(link, uint32(os.Getuid())); err == nil {
		t.Error("a symbolic link was accepted")
	}
	if _, err := OpenState("relative/dir", uint32(os.Getuid())); err == nil {
		t.Error("a relative path was accepted")
	}
}

func TestTryLockFailsAtOnceWhileTheLockIsHeld(t *testing.T) {
	s, _ := openTestState(t)
	first, err := s.TryLock(testKey)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := s.TryLock(testKey); !errors.Is(err, ErrBusy) {
		t.Fatalf("second TryLock: err = %v, want ErrBusy", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("the second TryLock waited %s", d)
	}
	other := testKey
	other.PID++
	second, err := s.TryLock(other)
	if err != nil {
		t.Fatalf("another JVM is locked out: %v", err)
	}
	second.Unlock()
	if err := first.Unlock(); err != nil {
		t.Fatal(err)
	}
	again, err := s.TryLock(testKey)
	if err != nil {
		t.Fatalf("lock after Unlock: %v", err)
	}
	again.Unlock()
}

func TestTryLockSeesALockOfAnotherStateHandle(t *testing.T) {
	s, path := openTestState(t)
	first, err := s.TryLock(testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Unlock()
	s2, err := OpenState(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := s2.TryLock(testKey); !errors.Is(err, ErrBusy) {
		t.Errorf("err = %v, want ErrBusy", err)
	}
}

func TestRecordRoundTrip(t *testing.T) {
	s, path := openTestState(t)
	want := testRecord()
	if err := s.WriteRecord(want); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadRecord(testKey)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("record = %+v, want %+v", got, want)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries after one write: %v", len(entries), entries)
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Errorf("record file mode = %v", info.Mode())
	}
	// A second write replaces the record, for example to add the session id.
	want.SessionID = "sid-2"
	if err := s.WriteRecord(want); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ReadRecord(testKey); got.SessionID != "sid-2" {
		t.Errorf("session id = %q after the update", got.SessionID)
	}
}

func TestReadRecordOfAMissingRecord(t *testing.T) {
	s, _ := openTestState(t)
	if _, err := s.ReadRecord(testKey); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want fs.ErrNotExist", err)
	}
}

func TestReadRecordRefusesUnsafeFiles(t *testing.T) {
	s, path := openTestState(t)
	if err := s.WriteRecord(testRecord()); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(path, testKey.String()+".session")
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadRecord(testKey); err == nil {
		t.Error("a record with mode 0644 was read")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, file); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadRecord(testKey); err == nil {
		t.Error("a symbolic link was followed")
	}
}

func TestReadRecordRefusesAContentThatDoesNotMatchItsName(t *testing.T) {
	s, path := openTestState(t)
	rec := testRecord()
	rec.PID = 999
	if err := s.WriteRecord(rec); err != nil {
		t.Fatal(err)
	}
	wrong := Key{BootID: rec.BootID, PID: 4242, StartTime: rec.StartTime}
	if err := os.Rename(filepath.Join(path, rec.Key().String()+".session"), filepath.Join(path, wrong.String()+".session")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadRecord(wrong); err == nil {
		t.Error("a record that names another process was accepted")
	}
}

func TestWriteRecordRejectsABadKey(t *testing.T) {
	s, _ := openTestState(t)
	for _, boot := range []string{"", "../x", "a/b", "UPPER", "a b"} {
		rec := testRecord()
		rec.BootID = boot
		if err := s.WriteRecord(rec); err == nil {
			t.Errorf("boot id %q was accepted", boot)
		}
	}
	rec := testRecord()
	rec.PID = 0
	if err := s.WriteRecord(rec); err == nil {
		t.Error("pid 0 was accepted")
	}
}

func TestRemoveRecord(t *testing.T) {
	s, _ := openTestState(t)
	if err := s.RemoveRecord(testKey); err != nil {
		t.Errorf("removing a missing record: %v", err)
	}
	if err := s.WriteRecord(testRecord()); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveRecord(testKey); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadRecord(testKey); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("record still there: %v", err)
	}
}

func TestRecordsListsOnlySessionRecords(t *testing.T) {
	s, path := openTestState(t)
	a := testRecord()
	b := testRecord()
	b.PID = 100
	for _, r := range []Record{a, b} {
		if err := s.WriteRecord(r); err != nil {
			t.Fatal(err)
		}
	}
	lock, err := s.TryLock(Key{BootID: testKey.BootID, PID: 7, StartTime: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Unlock()
	for _, name := range []string{"README", "bad.session", ".write-123"} {
		if err := os.WriteFile(filepath.Join(path, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := s.Records()
	if err != nil {
		t.Fatal(err)
	}
	want := []Key{b.Key(), a.Key()}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("keys = %v, want %v", keys, want)
	}
}

func TestRecordExpiry(t *testing.T) {
	r := testRecord()
	if r.Expired(r.Deadline.Add(-time.Second)) {
		t.Error("expired before the deadline")
	}
	if !r.Expired(r.Deadline) || !r.Expired(r.Deadline.Add(time.Hour)) {
		t.Error("not expired at or after the deadline")
	}
}

func TestCounter(t *testing.T) {
	s, _ := openTestState(t)
	c, err := s.Counter(testKey)
	if err != nil || c != (Counter{}) {
		t.Fatalf("new counter = %+v, %v", c, err)
	}
	t1 := time.Unix(1_700_000_000, 0).UTC()
	if c, err = s.AddAttach(testKey, t1); err != nil || c.Attaches != 1 || !c.LastAttach.Equal(t1) {
		t.Fatalf("first attach: %+v, %v", c, err)
	}
	t2 := t1.Add(2 * time.Minute)
	if c, err = s.AddAttach(testKey, t2); err != nil || c.Attaches != 2 || !c.LastAttach.Equal(t2) {
		t.Fatalf("second attach: %+v, %v", c, err)
	}
	got, err := s.Counter(testKey)
	if err != nil || got.Attaches != 2 || !got.LastAttach.Equal(t2) {
		t.Errorf("stored counter = %+v, %v", got, err)
	}
	other := testKey
	other.StartTime++
	if c, _ := s.Counter(other); c.Attaches != 0 {
		t.Error("a process with another start time shares the counter")
	}
}

func TestPruneRemovesFilesOfEndedProcesses(t *testing.T) {
	s, path := openTestState(t)
	gone := Key{BootID: testKey.BootID, PID: 1, StartTime: 1}
	alive := Key{BootID: testKey.BootID, PID: 2, StartTime: 2}
	held := Key{BootID: testKey.BootID, PID: 3, StartTime: 3}
	withRecord := Key{BootID: testKey.BootID, PID: 4, StartTime: 4}
	for _, k := range []Key{gone, alive, held, withRecord} {
		if _, err := s.AddAttach(k, time.Now()); err != nil {
			t.Fatal(err)
		}
		l, err := s.TryLock(k)
		if err != nil {
			t.Fatal(err)
		}
		if k != held {
			l.Unlock()
		} else {
			defer l.Unlock()
		}
	}
	rec := testRecord()
	rec.PID, rec.StartTime = withRecord.PID, withRecord.StartTime
	if err := s.WriteRecord(rec); err != nil {
		t.Fatal(err)
	}
	removed, err := s.Prune(func(k Key) bool { return k == alive })
	if err != nil {
		t.Fatal(err)
	}
	// gone: counter and lock file. held: its lock is taken. withRecord: the record is not ours to delete.
	if removed != 2 {
		t.Errorf("removed %d files, want 2", removed)
	}
	for name, want := range map[string]bool{
		gone.String() + ".count": false, gone.String() + ".lock": false,
		alive.String() + ".count": true, alive.String() + ".lock": true,
		held.String() + ".count": true, held.String() + ".lock": true,
		withRecord.String() + ".count": true, withRecord.String() + ".session": true,
	} {
		_, err := os.Stat(filepath.Join(path, name))
		if (err == nil) != want {
			t.Errorf("%s: exists = %v, want %v", name, err == nil, want)
		}
	}
}

func TestListingTwiceSeesTheSameFiles(t *testing.T) {
	s, _ := openTestState(t)
	if err := s.WriteRecord(testRecord()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		keys, err := s.Records()
		if err != nil {
			t.Fatal(err)
		}
		if len(keys) != 1 {
			t.Fatalf("listing %d found %d records, want 1", i+1, len(keys))
		}
	}
	// Prune lists the directory as well, after Records did.
	other := Key{BootID: testKey.BootID, PID: 5, StartTime: 5}
	if _, err := s.AddAttach(other, time.Now()); err != nil {
		t.Fatal(err)
	}
	removed, err := s.Prune(func(Key) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	if removed == 0 {
		t.Error("Prune found nothing to remove after Records listed the directory")
	}
}

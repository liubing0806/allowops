package credfile

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestCredential(t *testing.T) {
	for _, s := range []string{`{}`, `{"username":"x"}`, `{"username":"","password":"x"}`, `{"username":"x","password":null}`, `{"username":"x","password":"secret","dsn":"evil"}`, `{"username":"x","password":"secret"} {}`, `not secret json`} {
		_, err := Decode(strings.NewReader(s))
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Errorf("unexpected credential error: %v", err)
		}
	}
	c, err := Decode(strings.NewReader(`{"username":"reader","password":"a:b@/\\"}`))
	if err != nil || c.Username != "reader" || c.Password != "a:b@/\\" {
		t.Fatalf("decode credential: %+v, %v", c, err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "credential.json")
	if _, err := Read(path); err == nil {
		t.Fatal("accepted missing file")
	}
	if err := os.WriteFile(path, []byte(`{"username":"reader","password":""}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil {
		t.Fatal("accepted wide permissions")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	_, err = Read(path)
	if os.Geteuid() != 0 && err == nil {
		t.Fatal("accepted non-root owner")
	}
	if os.Geteuid() == 0 && err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(link); err == nil {
		t.Fatal("accepted symlink")
	}
	if _, err := Read(dir); err == nil {
		t.Fatal("accepted directory")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(fifo); err == nil {
		t.Fatal("accepted FIFO")
	}
}

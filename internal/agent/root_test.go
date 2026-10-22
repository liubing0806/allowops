package agent

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRootJoinTransfersIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires the root-test container")
	}
	uid, gid, err := allowopsAccount()
	if err != nil {
		t.Fatal(err)
	}
	g, _, config := startGateway(t, false)
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		t.Fatal(err)
	}
	if _, err := Join(context.Background(), config, "test-token", "root-join-test", dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if int(stat.Uid) != uid || int(stat.Gid) != gid || info.Mode().Perm() != 0600 {
		t.Fatalf("identity owner=%d:%d mode=%o", stat.Uid, stat.Gid, info.Mode().Perm())
	}
	if _, err := LoadIdentity(dir); err != nil {
		t.Fatal(err)
	}
	if err := CheckCommandUser(false); err == nil {
		t.Fatal("root run accepted")
	}
	if g.joins.Load() != 1 {
		t.Fatal("unexpected join count")
	}
	wrong := filepath.Join(t.TempDir(), "wrong")
	if err := os.Mkdir(wrong, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Join(context.Background(), config, "test-token", "wrong-owner", wrong); err == nil {
		t.Fatal("wrong directory owner accepted")
	}
	if g.joins.Load() != 1 {
		t.Fatal("token sent before directory validation")
	}
}

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
)

func TestAuditCommands(t *testing.T) {
	dsn := testpg.Start(t)
	ctx := context.Background()
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := audit.New(db.Pool, audit.Config{})
	var final []byte
	for i := 0; i < 3; i++ {
		e, err := a.Append(ctx, audit.Payload{SubjectID: "fixture", Operation: "execute_action", Resource: "fixture-host", Decision: "allow", Reason: "local CLI smoke"})
		if err != nil {
			t.Fatal(err)
		}
		final = e.Hash
	}
	binary, err := filepath.Abs("../../bin/allowops")
	if err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build allowops: %v\n%s", err, output)
	}
	run := func(args ...string) ([]byte, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, binary, args...)
		c.Env = append(os.Environ(), "ALLOWOPS_DATABASE_URL="+dsn)
		return c.CombinedOutput()
	}
	file := filepath.Join(t.TempDir(), "audit.jsonl")
	output, err := run("audit", "export", "--from", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), "--to", time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "--output", file)
	if err != nil {
		t.Fatalf("audit export: %v\n%s", err, output)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(data, []byte{'\n'}) != 3 {
		t.Fatalf("export lines=%d want 3", bytes.Count(data, []byte{'\n'}))
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("export permissions=%v err=%v", info, err)
	}
	t.Logf("./bin/allowops audit export --from <fixture> --to <fixture> --output <fixture>: exit 0, lines=3 bytes=%d", len(data))
	for _, args := range [][]string{
		{"audit", "verify", "--from-seq", "1", "--to-seq", "3"},
		{"audit", "verify", "--file", file, "--from-seq", "1", "--to-seq", "3", "--expected-final-hash", hex.EncodeToString(final)},
	} {
		output, err := run(args...)
		if err != nil {
			t.Fatalf("audit verify: %v\n%s", err, output)
		}
		var v audit.Verification
		if err := json.Unmarshal(output, &v); err != nil || !v.Valid || v.CheckedCount != 3 {
			t.Fatalf("verify=%s err=%v", output, err)
		}
		t.Logf("./bin/allowops audit verify (%s): exit 0: %s", map[bool]string{true: "file + external anchor", false: "PostgreSQL"}[len(args) > 6], strings.TrimSpace(string(output)))
	}
	if _, err := db.Pool.Exec(ctx, "UPDATE audit_events SET reason='tampered' WHERE seq=2"); err != nil {
		t.Fatal(err)
	}
	output, err = run("audit", "verify", "--from-seq", "1", "--to-seq", "3")
	if err == nil || !bytes.Contains(output, []byte(`"first_invalid_seq":2`)) {
		t.Fatalf("tampered CLI=%s err=%v", output, err)
	}
	t.Logf("tampered PostgreSQL verification: expected exit 1: %s", strings.TrimSpace(string(output)))
}

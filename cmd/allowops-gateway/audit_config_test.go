package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
	"gopkg.in/yaml.v3"
)

func TestAuditCursorKeyConfiguration(t *testing.T) {
	key := bytes.Repeat([]byte{42}, 32)
	path := filepath.Join(t.TempDir(), "cursor-key")
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatal(err)
	}
	var cfg configuration
	if err := yaml.Unmarshal([]byte("audit:\n  cursor_key_file: "+path+"\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	first, err := cfg.auditConfig(&logs)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cfg.auditConfig(&logs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.CursorKey, key) || !bytes.Equal(first.CursorKey, second.CursorKey) {
		t.Fatal("cursor key not loaded or stable across instances")
	}
	if logs.Len() != 0 {
		t.Fatal("configured key must not be logged")
	}
	cfg = configuration{}
	fallback, err := cfg.auditConfig(&logs)
	if err != nil || len(fallback.CursorKey) != 0 || !strings.Contains(logs.String(), "pagination cursors will be invalid after restart or across instances") {
		t.Fatalf("fallback key bytes=%d error=%v warning=%q", len(fallback.CursorKey), err, logs.String())
	}
	cfg.Audit.CursorKeyFile = path
	if err := os.WriteFile(path, key[:31], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.auditConfig(&logs); err == nil {
		t.Fatal("accepted invalid key length")
	}
	cfg.Audit.CursorKeyFile = path + "-missing"
	if _, err := cfg.auditConfig(&logs); err == nil {
		t.Fatal("accepted missing key")
	}
}

// Cursor validation must survive recreating the audit API with the file config.
func TestAuditCursorAcrossConfiguredInstances(t *testing.T) {
	ctx := context.Background()
	dsn := testpg.Start(t)
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{43}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	var cfg configuration
	cfg.Audit.CursorKeyFile = path
	fresh := func() *audit.Service {
		t.Helper()
		config, err := cfg.auditConfig(io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		return &audit.Service{Store: audit.New(db.Pool, config), Access: cursorTestAccess{}}
	}
	first := fresh()
	for range 3 {
		if _, err := first.Store.Append(ctx, audit.Payload{Operation: "cursor-config-test"}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := first.ListAuditEvents(ctx, connect.NewRequest(&v1.ListAuditEventsRequest{Page: &v1.PageRequest{PageSize: 1}}))
	if err != nil {
		t.Fatal(err)
	}
	token := page.Msg.Page.NextPageToken
	if token == "" {
		t.Fatal("expected pagination cursor")
	}
	for range 2 {
		page, err := fresh().ListAuditEvents(ctx, connect.NewRequest(&v1.ListAuditEventsRequest{Page: &v1.PageRequest{PageSize: 1, PageToken: token}}))
		if err != nil || len(page.Msg.Events) != 1 || page.Msg.Events[0].Seq != 2 {
			t.Fatalf("cross-instance cursor events=%v error=%v", page, err)
		}
	}
}

type cursorTestAccess struct{}

func (cursorTestAccess) Authorize(context.Context, http.Header, string) (string, error) {
	return "fixture", nil
}

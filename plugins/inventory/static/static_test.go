package static

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/liubing0806/allowops/plugin/inventory"
)

func TestExampleAndQuery(t *testing.T) {
	m := &Module{File: "../../../examples/topology.yaml"}
	if err := m.Provision(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	all, err := m.Resolve(context.Background(), inventory.Query{})
	if err != nil || len(all) != 3 || len(all[0].DependsOn) != 2 || all[1].Hosts[0] != "db-01" {
		t.Fatalf("entities=%+v error=%v", all, err)
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			for range 20 {
				results, err := m.Resolve(context.Background(), inventory.Query{Kind: "service"})
				if err != nil || len(results) != 1 || results[0].Attrs["team"] != "trade" || results[0].DependsOn[0] != "database/order-mysql" {
					t.Errorf("entities=%+v error=%v", results, err)
					return
				}
				results[0].Attrs["team"] = "changed"
				results[0].DependsOn[0] = "changed"
				db, _ := m.Resolve(context.Background(), inventory.Query{Kind: "database"})
				db[0].Hosts[0] = "changed"
			}
		})
	}
	wg.Wait()
	results, _ := m.Resolve(context.Background(), inventory.Query{Kind: "database"})
	if results[0].Hosts[0] != "db-01" {
		t.Fatal(results)
	}
}
func TestRejectFiles(t *testing.T) {
	for name, data := range map[string]string{
		"unknown":   "entities: [{kind: service, name: a, other: x}]",
		"duplicate": "entities: [{kind: service, name: a}, {kind: service, name: a}]",
		"kind":      "entities: [{kind: bad-kind, name: a}]",
		"name":      "entities: [{kind: service, name: ''}]",
		"long name": "entities: [{kind: service, name: '" + strings.Repeat("n", 129) + "'}]",
		"attr":      "entities: [{kind: service, name: a, attrs: {'bad key': x}}]",
		"selector":  "entities: [{kind: service, name: a, selector: '" + strings.Repeat("n", 513) + "'}]",
		"newline":   "entities: [{kind: service, name: a, depends_on: [\"b\\nc\"]}]",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "inventory.yaml")
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := (&Module{File: path}).Provision(context.Background(), nil); err == nil {
				t.Fatal("invalid file accepted")
			}
		})
	}
	if err := (&Module{File: t.TempDir()}).Provision(context.Background(), nil); err == nil {
		t.Fatal("directory accepted")
	}
}

func writeFile(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inventory.yaml")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestSizeLimit(t *testing.T) {
	head := "entities: [{kind: service, name: a}]\n#"
	exact := head + strings.Repeat("x", (4<<20)-len(head))
	if err := (&Module{File: writeFile(t, exact)}).Provision(context.Background(), nil); err != nil {
		t.Fatalf("file at the limit rejected: %v", err)
	}
	if err := (&Module{File: writeFile(t, exact+"x")}).Provision(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "4MB") {
		t.Fatalf("file over the limit: %v", err)
	}
}
func TestFIFODoesNotBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- (&Module{File: path}).Provision(context.Background(), nil) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Provision blocked on a FIFO")
	}
}
func TestErrorsOmitEntityContent(t *testing.T) {
	for name, data := range map[string]string{
		"duplicate": "entities: [{kind: service, name: password=hunter2}, {kind: service, name: password=hunter2}]",
		"invalid":   "entities: [{kind: service, name: password=hunter2, selector: '" + strings.Repeat("n", 513) + "'}]",
		"attr":      "entities: [{kind: service, name: a, attrs: {'hunter2 key': x}}]",
	} {
		t.Run(name, func(t *testing.T) {
			err := (&Module{File: writeFile(t, data)}).Provision(context.Background(), nil)
			if err == nil || strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), "inventory entity #") {
				t.Fatalf("error: %v", err)
			}
		})
	}
}

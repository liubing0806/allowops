package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestSDKSingleHostLabelsOverBudgetAreMarked(t *testing.T) {
	f := newTransportFixture(t)
	labels := map[string]string{}
	for i := range 128 {
		labels[fmt.Sprintf("label_%03d", i)] = strings.Repeat("<", 1024)
	}
	data, _ := json.Marshal(labels)
	if _, err := f.db.Pool.Exec(context.Background(), `UPDATE hosts SET authorization_labels=$1 WHERE hostname='web-01'`, data); err != nil {
		t.Fatal(err)
	}
	c, _ := f.client(t, f.admin, nil)
	result := call(t, c, "hosts_search", map[string]any{"hostname": "web-01"})
	encoded, _ := json.Marshal(result)
	if result.IsError || len(encoded) > resultByteLimit {
		t.Fatalf("host result isError=%v bytes=%d content=%v", result.IsError, len(encoded), result.StructuredContent)
	}
	content := content(t, result)
	hosts := content["hosts"].([]any)
	if len(hosts) != 1 {
		t.Fatalf("hosts=%v", hosts)
	}
	host := hosts[0].(map[string]any)
	kept := host["labels"].(map[string]any)
	if host["host"] != "web-01" || host["online"] != false || host["labels_truncated"] != true || len(kept) == 0 || len(kept) >= 128 {
		t.Fatalf("host=%v", host)
	}
	if content["total"] != float64(1) || content["label_counts_truncated"] != true {
		t.Fatalf("metadata=%v", content)
	}
}

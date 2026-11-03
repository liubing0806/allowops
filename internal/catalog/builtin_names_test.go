package catalog

import (
	"slices"
	"testing"
)

func TestBuiltinNamesListsEveryHandlerSorted(t *testing.T) {
	want := []string{
		"alertmanager_alerts",
		"dremio_diag",
		"dremio_query",
		"http_get",
		"log_query",
		"log_search",
		"mysql_query",
		"prometheus_query",
		"redis_command",
		"starrocks_diag",
		"starrocks_query",
	}
	if got := BuiltinNames(); !slices.Equal(got, want) {
		t.Fatalf("BuiltinNames()=%v want %v", got, want)
	}
}

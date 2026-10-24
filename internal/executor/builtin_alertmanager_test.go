package executor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuiltinAlertmanagerE2E(t *testing.T) {
	status := 200
	body := fmt.Sprintf(`[
 {"startsAt":"2026-10-23T02:00:00Z","status":{"state":"active"},"labels":{"alertname":"First","severity":"critical"},"annotations":{"summary":"key %s"}},
 {"startsAt":"2026-10-23T03:00:00Z","status":{"state":"active"},"labels":{"alertname":"Second"}},
 {"startsAt":"2026-10-23T04:00:00Z","status":{"state":"active"},"labels":{"alertname":"Third"}}]`, builtinSecret)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	defer s.Close()
	a := localBuiltinAction("alertmanager_alerts", map[string]any{"address": s.URL, "max_alerts": 2})
	input := map[string]any{"active": true, "silenced": false, "inhibited": false}

	r, err := RunWithFilters(context.Background(), a, input, nil, nil)
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("run: %+v %v", r, err)
	}
	if strings.Contains(r.Stdout, "AKIA") || !strings.Contains(r.Stdout, builtinSecretMask) {
		t.Fatalf("secret must be redacted: %q", r.Stdout)
	}
	if !r.Truncated || !r.ResourceLimitReached || strings.Contains(r.Stdout, "Third") || !strings.Contains(r.Stderr, "2 of 3") {
		t.Fatalf("max_alerts truncation: %+v", r)
	}

	r, err = RunWithFilters(context.Background(), a, input, map[string]any{"match": "Second", "count": true}, nil)
	if err != nil || r.Stdout != "1\n" {
		t.Fatalf("filters apply to rendered rows: %+v %v", r, err)
	}

	status, body = 503, "unavailable"
	r, err = RunWithFilters(context.Background(), a, input, nil, nil)
	if err != nil || r.ExitCode != 1 || !strings.Contains(r.Stderr, "HTTP 503") || r.Stdout != "" {
		t.Fatalf("HTTP error: %+v %v", r, err)
	}
}

package console

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSPARoutesAndStaticCache(t *testing.T) {
	handler := Handler()
	for _, route := range []string{"/", "/login", "/hosts/web.example.org", "/jobs/job-123", "/index.html"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, route, nil))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `<div id="root"></div>`) {
			t.Fatalf("%s: status=%d body=%q", route, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-cache" || w.Header().Get("Content-Security-Policy") != contentSecurityPolicy {
			t.Fatalf("%s: cache or CSP missing: %v", route, w.Header())
		}
	}
	entries, err := fs.ReadDir(assets, "dist/assets")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/assets/"+entry.Name(), nil))
		if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatalf("asset %s: status=%d headers=%v", entry.Name(), w.Code, w.Header())
		}
	}
	for _, route := range []string{"/assets", "/assets/missing.js", "/missing.js"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, route, nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s: status=%d; want 404", route, w.Code)
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: status=%d; want 405", w.Code)
	}
}

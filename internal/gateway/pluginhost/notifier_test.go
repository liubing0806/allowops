package pluginhost

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/plugin"
	"github.com/liubing0806/allowops/plugin/notifier"
)

func notifierCA(t *testing.T, server *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "webhook-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNotifierEgressHTTPSPostsAndRedirects(t *testing.T) {
	requests := make(chan string, 16)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Method + " " + r.URL.Path
		var status int
		if _, err := fmt.Sscanf(r.URL.Path, "/redirect/%d", &status); err == nil {
			http.Redirect(w, r, "/deliver", status)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	cfg := Config{Egress: []string{server.URL}, CAFile: notifierCA(t, server), Timeout: time.Second, AllowCrossOriginRedirects: true}
	plaintext := cfg
	plaintext.Egress = []string{server.URL, "http://127.0.0.1"}
	if _, err := egressConfig(plaintext, true); !errors.Is(err, errEgress) {
		t.Fatalf("notifier plaintext egress configuration returned %v", err)
	}
	for _, disabled := range []bool{false, true} {
		configured := config(t, "id: webhook\nmodule: notifier.host_test")
		configured.Egress, configured.Disabled = plaintext.Egress, disabled
		if _, err := New(t.Context(), []Config{configured}, testDeps()); !errors.Is(err, errEgress) {
			t.Fatalf("notifier with disabled=%v accepted plaintext egress: %v", disabled, err)
		}
	}
	request := func(client *http.Client, method, path string, wantErr bool) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, server.URL+path, strings.NewReader("example request"))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		if wantErr && !errors.Is(err, errEgress) || !wantErr && err != nil {
			t.Fatalf("%s %s got %v, expected denied=%t", method, path, err, wantErr)
		}
	}
	client := func(c Config, mode bool) *http.Client {
		t.Helper()
		cl, err := newEgressClient(c, mode, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(cl.CloseIdleConnections)
		return cl
	}
	request(client(cfg, true), http.MethodPost, "/deliver", true)
	readonly := client(cfg, false)
	request(readonly, http.MethodPost, "/deliver", true)
	request(readonly, http.MethodGet, "/deliver", false)
	cfg.AllowPrivateEgress = true
	notifyClient := client(cfg, true)
	request(notifyClient, http.MethodPost, "/deliver", false)
	request(notifyClient, http.MethodHead, "/deliver", false)
	request(notifyClient, http.MethodPut, "/deliver", true)
	want := []string{"GET /deliver", "POST /deliver", "HEAD /deliver"}
	for _, status := range []int{301, 302, 303, 307, 308} {
		path := fmt.Sprintf("/redirect/%d", status)
		request(notifyClient, http.MethodPost, path, true)
		want = append(want, "POST "+path)
	}
	close(requests)
	var actual []string
	for request := range requests {
		actual = append(actual, request)
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("requests = %v, want %v", actual, want)
	}
}

func TestNotifierEgressPrivateIPPolicy(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "::1", "10.0.0.8", "192.168.1.2", "100.64.0.8", "fd00::1", "::ffff:10.0.0.1"} {
		ip := netip.MustParseAddr(raw)
		if allowedIP(ip, true, false, true) || !allowedIP(ip, true, true, true) {
			t.Errorf("notifier private literal rule failed for %s", ip)
		}
	}
	for _, raw := range []string{"0.0.0.0", "::", "169.254.169.254", "fe80::1", "100.100.100.200", "fd00:ec2::254", "64:ff9b::1", "64:ff9b:1::1", "224.0.0.1", "ff02::1"} {
		ip := netip.MustParseAddr(raw)
		if allowedIP(ip, true, true, true) || allowedIP(ip, false, true, true) {
			t.Errorf("notifier allowed forbidden IP %s", ip)
		}
	}
}

type runtimeNotifier struct {
	Mode string `yaml:"mode"`
	URL  string `yaml:"url"`
	host plugin.Host
}

func (runtimeNotifier) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "notifier.host_test", New: func() plugin.Module { return new(runtimeNotifier) }}
}

func (n *runtimeNotifier) Provision(_ context.Context, host plugin.Host) error {
	if n.Mode == "unhealthy" {
		return errors.New("fixture unavailable")
	}
	n.host = host
	return nil
}

const fixturePrivateData = "https://webhook.invalid/opaque-path?key=opaque-query-token opaque-upstream-response"

func (n *runtimeNotifier) Send(ctx context.Context, _ notifier.Event) error {
	switch n.Mode {
	case "panic":
		panic(fixturePrivateData)
	case "fail":
		return errors.New(fixturePrivateData)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, nil)
	if err != nil {
		return err
	}
	response, err := n.host.HTTPClient().Do(req)
	if err != nil {
		return err
	}
	return response.Body.Close()
}

type invalidNotifier struct{}

func (invalidNotifier) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "notifier.wrong_test", New: func() plugin.Module { return new(invalidNotifier) }}
}

func init() {
	plugin.Register(runtimeNotifier{})
	plugin.Register(invalidNotifier{})
}

func TestNotifierHostConcurrentFanoutAndFailures(t *testing.T) {
	requests := make(chan string, 3)
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.URL.Path
		if r.URL.Path == "/timeout" {
			<-r.Context().Done()
			return
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	ca := notifierCA(t, server)
	configs := []Config{{ID: "invalid", Module: "notifier.wrong_test"}}
	if _, err := New(t.Context(), configs, testDeps()); err == nil {
		t.Fatal("notifier module without Sender was accepted")
	}
	configs = nil
	for _, item := range []struct{ id, mode string }{{"one", ""}, {"two", ""}, {"timeout", ""}, {"failed", "fail"}, {"panicked", "panic"}, {"unhealthy", "unhealthy"}} {
		cfg := config(t, fmt.Sprintf("id: %s\nmodule: notifier.host_test\nconfig: {mode: %q, url: %q}", item.id, item.mode, server.URL+"/"+item.id))
		cfg.Egress, cfg.CAFile, cfg.AllowPrivateEgress = []string{server.URL}, ca, true
		if item.id == "timeout" {
			cfg.Timeout = 300 * time.Millisecond
		}
		configs = append(configs, cfg)
	}
	var logs bytes.Buffer
	host, err := New(t.Context(), configs, Deps{Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close(t.Context())
	if got := host.NotifierSources(); !reflect.DeepEqual(got, []string{"one", "two", "timeout", "failed", "panicked"}) {
		t.Fatalf("sources = %v", got)
	}
	result := make(chan []SourceError, 1)
	go func() { result <- host.Notify(t.Context(), notifier.Event{Type: notifier.EventApprovalRequested}) }()
	paths := make(map[string]bool)
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for range 3 {
		select {
		case path := <-requests:
			paths[path] = true
		case <-deadline.C:
			t.Fatal("notifier requests did not start concurrently")
		}
	}
	close(release)
	for _, path := range []string{"/one", "/two", "/timeout"} {
		if !paths[path] {
			t.Errorf("missing request for %s", path)
		}
	}
	select {
	case got := <-result:
		want := []SourceError{{"timeout", "timeout"}, {"failed", "failed"}, {"panicked", "panic"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("failures = %v, want %v", got, want)
		}
	case <-deadline.C:
		t.Fatal("notifier fanout did not honor the instance timeout")
	}
	host.Close(t.Context())
	for _, private := range []string{"opaque-path", "opaque-query-token", "opaque-upstream-response", "webhook.invalid"} {
		if strings.Contains(logs.String(), private) {
			t.Error("notifier logs exposed private data")
		}
	}
}

func TestNotifierHostConcurrencyLimit(t *testing.T) {
	started, release := make(chan struct{}, 2), make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	cfg := config(t, fmt.Sprintf("id: limited\nmodule: notifier.host_test\nconfig: {url: %q}", server.URL))
	cfg.Egress, cfg.CAFile, cfg.AllowPrivateEgress = []string{server.URL}, notifierCA(t, server), true
	cfg.MaxConcurrency = 1
	host, err := New(t.Context(), []Config{cfg}, testDeps())
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close(t.Context())
	first := make(chan []SourceError, 1)
	go func() { first <- host.Notify(t.Context(), notifier.Event{}) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first notification did not reach the upstream")
	}
	competing, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if got := host.Notify(competing, notifier.Event{}); !reflect.DeepEqual(got, []SourceError{{"limited", "timeout"}}) {
		t.Fatalf("competing notification = %v", got)
	}
	select {
	case <-started:
		t.Fatal("competing notification bypassed the instance semaphore")
	default:
	}
	close(release)
	select {
	case got := <-first:
		if len(got) != 0 {
			t.Fatalf("first notification failed: %v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("first notification did not finish")
	}
	if got := host.Notify(t.Context(), notifier.Event{}); len(got) != 0 {
		t.Fatalf("notification after releasing semaphore failed: %v", got)
	}
}

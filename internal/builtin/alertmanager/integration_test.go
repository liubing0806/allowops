package alertmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// alertmanagerImage is pinned: output and filter semantics are specified
// against this release.
const alertmanagerImage = "prom/alertmanager:v0.34.1"

// startAlertmanager starts a throwaway Alertmanager on the local Docker socket
// and returns its base URL. Only the local Unix socket is used, regardless of
// remote Docker environment settings. No existing service is accepted.
func startAlertmanager(t *testing.T) string {
	t.Helper()
	const socket = "/var/run/docker.sock"
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer probeCancel()
	probe, err := (&net.Dialer{}).DialContext(probeCtx, "unix", socket)
	if err != nil {
		t.Skipf("local Docker unavailable: %v", err)
	}
	probe.Close()
	cli, err := client.New(client.WithHost("unix://" + socket))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := cli.Ping(probeCtx, client.PingOptions{}); err != nil {
		t.Skipf("local Docker unavailable: %v", err)
	}
	t.Setenv("DOCKER_HOST", "unix://"+socket)
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	t.Setenv("TESTCONTAINERS_HOST_OVERRIDE", "127.0.0.1")
	t.Setenv("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE", socket)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        alertmanagerImage,
			ExposedPorts: []string{"9093/tcp"},
			HostConfigModifier: func(h *container.HostConfig) {
				h.PortBindings = network.PortMap{network.MustParsePort("9093/tcp"): {{HostIP: netip.MustParseAddr("127.0.0.1")}}}
			},
			WaitingFor: wait.ForHTTP("/-/ready").WithPort("9093/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	if c != nil {
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
			defer done()
			if err := c.Terminate(cleanup); err != nil {
				t.Errorf("terminate local Alertmanager: %v", err)
			}
		})
	}
	if err != nil {
		t.Fatalf("start local Alertmanager: %v", err)
	}
	port, err := c.MappedPort(ctx, "9093/tcp")
	if err != nil {
		t.Fatal(err)
	}
	return "http://" + net.JoinHostPort("127.0.0.1", port.Port())
}

// post is a fixture write. The handler under test only issues GET requests.
func post(t *testing.T, url string, payload any) []byte {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: HTTP %d: %s", url, resp.StatusCode, body)
	}
	return body
}

type fixtureAlert struct {
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	StartsAt     string            `json:"startsAt"`
	GeneratorURL string            `json:"generatorURL,omitempty"`
}

func TestAlertmanagerIntegration(t *testing.T) {
	address := startAlertmanager(t)
	now := time.Now().UTC().Truncate(time.Second)
	at := func(ago time.Duration) string { return now.Add(-ago).Format(time.RFC3339) }
	post(t, address+"/api/v2/alerts", []fixtureAlert{
		{Labels: map[string]string{"alertname": "HighLatency", "severity": "critical", "job": "api", "instance": "10.0.0.5:9100"},
			Annotations:  map[string]string{"summary": "p99 above 1s", "description": "api\tslow\non 10.0.0.5"},
			StartsAt:     at(time.Hour),
			GeneratorURL: "http://prometheus.example:9090/graph?g0.expr=histogram_quantile%280.99%2C+rate%28latency_bucket%5B5m%5D%29%29+%3E+1&g0.tab=1"},
		{Labels: map[string]string{"alertname": "DiskFull", "severity": "warning", "instance": "10.0.0.6:9100"},
			Annotations: map[string]string{"summary": "disk 95%"}, StartsAt: at(2 * time.Hour)},
		{Labels: map[string]string{"alertname": "NoisyNeighbor", "severity": "info", "instance": "10.0.0.7:9100"},
			Annotations: map[string]string{"summary": "silenced noise"}, StartsAt: at(30 * time.Minute),
			GeneratorURL: "http://prometheus.example:9090/graph?g0.expr=up%3D%3D0&g0.tab=%zz"},
	})
	var silence struct {
		SilenceID string `json:"silenceID"`
	}
	if err := json.Unmarshal(post(t, address+"/api/v2/silences", map[string]any{
		"matchers":  []map[string]any{{"name": "alertname", "value": "NoisyNeighbor", "isRegex": false, "isEqual": true}},
		"startsAt":  now.Add(-time.Minute).Format(time.RFC3339),
		"endsAt":    now.Add(time.Hour).Format(time.RFC3339),
		"createdBy": "integration-test",
		"comment":   "fixture",
	}), &silence); err != nil || silence.SilenceID == "" {
		t.Fatalf("silence fixture: %q %v", silence.SilenceID, err)
	}
	cfg := Config{Address: address, Timeout: 10 * time.Second}

	// Silencing is applied asynchronously after the alert is ingested.
	states := func(p Params) []string {
		r := run(t, cfg, p, nil)
		var names []string
		for _, line := range lines(r.Stdout) {
			f := strings.Split(line, "\t")
			names = append(names, f[2]+":"+f[1])
		}
		return names
	}
	deadline := time.Now().Add(30 * time.Second)
	for len(states(Params{Silenced: true})) != 1 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}

	t.Run("active_only_is_sorted_by_start", func(t *testing.T) {
		r := run(t, cfg, Params{Active: true}, nil)
		got := lines(r.Stdout)
		if r.ExitCode != 0 || r.Truncated || len(got) != 2 {
			t.Fatalf("result = %+v", r)
		}
		wantFirst := strings.Join([]string{at(2 * time.Hour), "active", "DiskFull", "warning", `{instance="10.0.0.6:9100"}`, "disk 95%", "", "", "", ""}, "\t")
		wantSecond := strings.Join([]string{at(time.Hour), "active", "HighLatency", "critical", `{instance="10.0.0.5:9100",job="api"}`, "p99 above 1s", `api\tslow\non 10.0.0.5`, "", "",
			"histogram_quantile(0.99, rate(latency_bucket[5m])) > 1"}, "\t")
		if got[0] != wantFirst || got[1] != wantSecond {
			t.Fatalf("got:\n%s\nwant:\n%s\n%s", r.Stdout, wantFirst, wantSecond)
		}
	})
	t.Run("silenced_only", func(t *testing.T) {
		r := run(t, cfg, Params{Silenced: true}, nil)
		got := lines(r.Stdout)
		if len(got) != 1 {
			t.Fatalf("stdout = %q", r.Stdout)
		}
		f := strings.Split(got[0], "\t")
		// A bad escape in an unrelated parameter must not hide the expression.
		if f[1] != "suppressed" || f[2] != "NoisyNeighbor" || f[7] != silence.SilenceID || f[8] != "" || f[9] != "up==0" {
			t.Fatalf("fields = %q", f)
		}
	})
	t.Run("all_states", func(t *testing.T) {
		got := states(Params{Active: true, Silenced: true, Inhibited: true})
		want := []string{"DiskFull:active", "HighLatency:active", "NoisyNeighbor:suppressed"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
	t.Run("no_state_selected", func(t *testing.T) {
		if got := states(Params{}); len(got) != 0 {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("filters", func(t *testing.T) {
		for _, tc := range []struct {
			filter []string
			want   string
		}{
			{[]string{`severity="critical"`}, "HighLatency:active"},
			{[]string{`severity=~"critical|warning"`, `job="api"`}, "HighLatency:active"},
			{[]string{`alertname=~"Disk.*"`}, "DiskFull:active"},
			{[]string{`severity="none"`}, ""},
		} {
			got := states(Params{Active: true, Filter: tc.filter})
			if strings.Join(got, ",") != tc.want {
				t.Errorf("filter %v: got %v, want %q", tc.filter, got, tc.want)
			}
		}
	})
	t.Run("max_alerts", func(t *testing.T) {
		c := cfg
		c.MaxAlerts = 1
		r := run(t, c, Params{Active: true, Silenced: true}, nil)
		if !r.Truncated || len(lines(r.Stdout)) != 1 || !strings.Contains(r.Stdout, "DiskFull") || !strings.Contains(r.Stderr, "1 of 3") {
			t.Fatalf("result = %+v", r)
		}
	})
	t.Run("invalid_filter", func(t *testing.T) {
		r, err := Run(context.Background(), cfg, Params{Active: true, Filter: []string{"not a matcher("}}, nil)
		if err != nil || r.ExitCode != 1 || !strings.Contains(r.Stderr, "HTTP 400") {
			t.Fatalf("result = %+v, err = %v", r, err)
		}
	})
	t.Run("path_prefix_not_served", func(t *testing.T) {
		c := cfg
		c.Address = address + "/missing"
		r, err := Run(context.Background(), c, Params{Active: true}, nil)
		if err != nil || r.ExitCode != 1 || !strings.Contains(r.Stderr, "HTTP 404") {
			t.Fatalf("result = %+v, err = %v", r, err)
		}
	})
}

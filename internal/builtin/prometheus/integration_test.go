package prometheus

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/builtin/apiclient"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// prometheusImage is pinned by version and digest.
const prometheusImage = "prom/prometheus:v3.14.0@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0"

const prometheusConfigYAML = `global:
  scrape_interval: 1s
  evaluation_interval: 1s
rule_files:
  - /etc/prometheus/rules.yml
scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ['127.0.0.1:9090']
`

const prometheusRulesYAML = `groups:
  - name: fixture
    rules:
      - alert: AlwaysFiring
        expr: vector(1)
        labels:
          severity: page
        annotations:
          summary: fixture alert fires
      - record: fixture:up:sum
        expr: sum(up)
`

// Only the local Unix socket is used, regardless of remote Docker environment
// settings. The container's port is published on 127.0.0.1 only.
func TestPrometheusIntegration(t *testing.T) {
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
			Image:        prometheusImage,
			ExposedPorts: []string{"9090/tcp"},
			Cmd: []string{
				"--config.file=/etc/prometheus/prometheus.yml",
				"--storage.tsdb.path=/prometheus",
				"--storage.tsdb.retention.time=1h",
			},
			Files: []testcontainers.ContainerFile{
				{Reader: strings.NewReader(prometheusConfigYAML), ContainerFilePath: "/etc/prometheus/prometheus.yml", FileMode: 0o644},
				{Reader: strings.NewReader(prometheusRulesYAML), ContainerFilePath: "/etc/prometheus/rules.yml", FileMode: 0o644},
			},
			HostConfigModifier: func(h *container.HostConfig) {
				h.PortBindings = network.PortMap{network.MustParsePort("9090/tcp"): {{HostIP: netip.MustParseAddr("127.0.0.1")}}}
			},
			WaitingFor: wait.ForLog("Server is ready to receive web requests.").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	if c != nil {
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
			defer done()
			if err := c.Terminate(cleanup); err != nil {
				t.Errorf("terminate local Prometheus: %v", err)
			}
		})
	}
	if err != nil {
		t.Fatalf("start local Prometheus: %v", err)
	}

	mapped, err := c.MappedPort(ctx, "9090/tcp")
	if err != nil {
		t.Fatal(err)
	}
	// The target is the container's own listener; the client uses the mapped port.
	const target = "127.0.0.1:9090"
	address := net.JoinHostPort("127.0.0.1", mapped.Port())
	cfg := func(api string) Config {
		return Config{API: api, Config: apiclient.Config{Address: "http://" + address}}
	}
	run := func(t *testing.T, cfg Config, p Params) Result {
		t.Helper()
		r, err := Run(ctx, cfg, p)
		if err != nil {
			t.Fatalf("Run: %v (stderr %q)", err, r.Stderr)
		}
		return r
	}
	// eventually repeats the query until check accepts the output, because the
	// first scrape and rule evaluation happen after startup.
	eventually := func(t *testing.T, cfg Config, p Params, check func(Result) bool) Result {
		t.Helper()
		var r Result
		for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
			r = run(t, cfg, p)
			if r.ExitCode == 0 && check(r) {
				return r
			}
		}
		t.Fatalf("condition not met; last result %+v", r)
		return r
	}
	upSeries := fmt.Sprintf(`up{instance="%s",job="prometheus"}`, target)

	t.Run("query", func(t *testing.T) {
		r := eventually(t, cfg("query"), Params{Query: "up"}, func(r Result) bool { return strings.Contains(r.Stdout, upSeries) })
		rows := lines(r.Stdout)
		fields := strings.Split(rows[1], "\t")
		if !strings.HasPrefix(rows[0], "# api=query time=") || len(fields) != 3 || fields[0] != upSeries || fields[2] != "1" {
			t.Errorf("stdout = %q", r.Stdout)
		}
		if _, err := time.Parse(timeLayout, fields[1]); err != nil {
			t.Errorf("sample time %q: %v", fields[1], err)
		}
		scalar := run(t, cfg("query"), Params{Query: "1 + 2"})
		if rows := lines(scalar.Stdout); len(rows) != 2 || !strings.HasSuffix(rows[1], "\t3") {
			t.Errorf("scalar = %q", scalar.Stdout)
		}
		matrix := eventually(t, cfg("query"), Params{Query: "up[30s]"}, func(r Result) bool { return strings.Count(r.Stdout, upSeries) >= 2 })
		if !strings.Contains(matrix.Stdout, upSeries) {
			t.Errorf("range selector = %q", matrix.Stdout)
		}
	})

	t.Run("query_range", func(t *testing.T) {
		summary := eventually(t, cfg("query_range"), Params{Query: "up", Start: "now-2m", Step: 15 * time.Second, HasStep: true, Summary: true},
			func(r Result) bool { return strings.Contains(r.Stdout, upSeries) })
		rows := lines(summary.Stdout)
		if !strings.HasPrefix(rows[0], "# api=query_range start=") || !strings.HasSuffix(rows[0], " step=15s") {
			t.Errorf("header = %q", rows[0])
		}
		if want := upSeries + "\t1\t1\t1\t1"; rows[1] != want {
			t.Errorf("summary = %q; want %q", rows[1], want)
		}
		points := run(t, cfg("query_range"), Params{Query: "up", Start: "now-2m", Step: 15 * time.Second, HasStep: true})
		for _, row := range lines(points.Stdout)[1:] {
			if fields := strings.Split(row, "\t"); len(fields) != 3 || fields[0] != upSeries || fields[2] != "1" {
				t.Errorf("point row = %q", row)
			}
		}
		derived := run(t, cfg("query_range"), Params{Query: "up", Start: "now-1h"})
		if !strings.Contains(lines(derived.Stdout)[0], " step=15s") {
			t.Errorf("derived step header = %q", lines(derived.Stdout)[0])
		}
	})

	t.Run("series_labels_and_label_values", func(t *testing.T) {
		series := eventually(t, cfg("series"), Params{Match: []string{"up"}}, func(r Result) bool { return strings.Contains(r.Stdout, upSeries) })
		if rows := lines(series.Stdout); len(rows) != 2 || rows[1] != upSeries {
			t.Errorf("series = %q", series.Stdout)
		}
		all := cfg("label_values")
		all.MaxSeries = 1000
		names := run(t, all, Params{Label: "__name__"})
		if got := lines(names.Stdout); !containsRow(got, "up") || !containsRow(got, "scrape_duration_seconds") {
			t.Errorf("metric names = %q", names.Stdout)
		}
		jobs := run(t, cfg("label_values"), Params{Label: "job", Match: []string{"up"}})
		if rows := lines(jobs.Stdout); len(rows) != 2 || rows[1] != "prometheus" {
			t.Errorf("job values = %q", jobs.Stdout)
		}
		labels := run(t, cfg("labels"), Params{})
		if got := lines(labels.Stdout); !containsRow(got, "__name__") || !containsRow(got, "job") || !containsRow(got, "instance") {
			t.Errorf("labels = %q", labels.Stdout)
		}
		limited := cfg("series")
		limited.MaxSeries = 3
		cut := run(t, limited, Params{Match: []string{`{__name__=~".+"}`}})
		if !cut.Truncated || len(lines(cut.Stdout)) != 4 || !strings.Contains(cut.Stderr, "returned 3") {
			t.Errorf("truncated series = %+v", cut)
		}
	})

	t.Run("rules_and_alerts", func(t *testing.T) {
		rules := eventually(t, cfg("rules"), Params{}, func(r Result) bool { return strings.Contains(r.Stdout, "AlwaysFiring\tok\tfiring") })
		if !strings.Contains(rules.Stdout, "fixture\talerting\tAlwaysFiring\tok\tfiring\t\tvector(1)\n") ||
			!strings.Contains(rules.Stdout, "fixture\trecording\tfixture:up:sum\tok\t\t\tsum(up)\n") {
			t.Errorf("rules = %q", rules.Stdout)
		}
		recording := run(t, cfg("rules"), Params{RuleType: "record"})
		if strings.Contains(recording.Stdout, "AlwaysFiring") || !strings.Contains(recording.Stdout, "fixture:up:sum") {
			t.Errorf("record rules = %q", recording.Stdout)
		}
		alerts := eventually(t, cfg("alerts"), Params{}, func(r Result) bool { return strings.Contains(r.Stdout, "AlwaysFiring\tfiring\t") })
		row := lines(alerts.Stdout)[1]
		fields := strings.Split(row, "\t")
		if len(fields) != 6 || fields[3] != "1e+00" || fields[4] != `{alertname="AlwaysFiring",severity="page"}` || fields[5] != "fixture alert fires" {
			t.Errorf("alert row = %q", row)
		}
	})

	t.Run("targets", func(t *testing.T) {
		targets := eventually(t, cfg("targets"), Params{}, func(r Result) bool { return strings.Contains(r.Stdout, "\tup\t") })
		want := "prometheus\t" + target + "\tup\t"
		if row := lines(targets.Stdout)[1]; !strings.HasPrefix(row, want) || !strings.HasSuffix(row, "\t\thttp://"+target+"/metrics") {
			t.Errorf("target row = %q; want prefix %q", row, want)
		}
	})

	t.Run("errors_and_timeout", func(t *testing.T) {
		bad := run(t, cfg("query"), Params{Query: "up{"})
		if bad.ExitCode != 1 || bad.StatusCode != http.StatusBadRequest || !strings.Contains(bad.Stderr, "errorType=bad_data") {
			t.Errorf("parse error = %+v", bad)
		}
		slow := cfg("query")
		slow.Timeout = time.Second
		started := time.Now()
		// Prometheus gets timeout=1 and the client times out after 1s as well, so
		// the failure is either errorType=timeout from the server or a client error.
		// A subquery over every series with a 1 ms step does not finish in 1s.
		r, err := Run(ctx, slow, Params{Query: `count(count_over_time({__name__=~".+"}[1h:1ms]))`})
		if (err == nil && r.ExitCode == 0) || time.Since(started) > 10*time.Second {
			t.Errorf("slow query = %+v, %v after %v", r, err, time.Since(started))
		}
		t.Logf("slow query: err=%v stderr=%q", err, r.Stderr)
	})
}

func containsRow(rows []string, want string) bool {
	for _, row := range rows {
		if row == want {
			return true
		}
	}
	return false
}

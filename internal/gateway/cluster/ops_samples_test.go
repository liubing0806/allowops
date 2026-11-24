package cluster

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestOpsSampleDFH(t *testing.T) {
	// 8 healthy hosts (~40-44% /data), 1 outlier host (96% /data), 1 host with extra mount (/mnt/backup).
	tasks := make([]TaskInput, 0, 10)
	for i := 0; i < 9; i++ {
		usePct := 40 + i%5
		avail := 115 - i%5
		used := 85 + i%5
		if i == 8 {
			usePct = 96
			used = 192
			avail = 8
		}
		out := fmt.Sprintf(
			"Filesystem      Size  Used Avail Use%% Mounted on\n"+
				"/dev/sda1        50G   20G   28G  42%% /\n"+
				"/dev/sdb1       200G  %3dG  %3dG  %2d%% /data\n"+
				"tmpfs           7.8G  1.2M  7.8G   1%% /run\n",
			used, avail, usePct,
		)
		tasks = append(tasks, makeSucceededTask(fmt.Sprintf("df-%02d", i), fmt.Sprintf("storage-%02d", i), out, ""))
	}
	extraMount := "Filesystem      Size  Used Avail Use% Mounted on\n" +
		"/dev/sda1        50G   20G   28G  42% /\n" +
		"/dev/sdb1       200G   86G  114G  43% /data\n" +
		"tmpfs           7.8G  1.2M  7.8G   1% /run\n" +
		"/dev/sdc1       500G  100G  400G  20% /mnt/backup\n"
	tasks = append(tasks, makeSucceededTask("df-09", "storage-09", extraMount, ""))

	res := Cluster(tasks, ClusterOptions{Grouping: GroupingNormalized})
	assertHostConservation(t, tasks, res)

	if len(res.Groups) != 2 {
		t.Fatalf("expected 2 groups (extra mount minority + 9-host metric_outlier), got %d: %+v", len(res.Groups), res.Groups)
	}
	// Group 0: minority_cluster (storage-09 with extra mount).
	if res.Groups[0].Severity != SeverityAnomaly || res.Groups[0].AnomalyReason != ReasonMinorityCluster || res.Groups[0].HostCount != 1 {
		t.Fatalf("expected minority_cluster first, got %+v", res.Groups[0])
	}
	if res.Groups[0].Hosts[0] != "storage-09" {
		t.Fatalf("expected storage-09 in minority cluster, got %v", res.Groups[0].Hosts)
	}
	// Group 1: 9-host group elevated to Tier 1 metric_outlier for storage-08 (96%).
	g1 := res.Groups[1]
	if g1.Severity != SeverityAnomaly || g1.AnomalyReason != ReasonMetricOutlier || g1.HostCount != 9 {
		t.Fatalf("expected 9-host metric_outlier second, got %+v", g1)
	}
	found96Outlier := false
	for _, v := range g1.Variances {
		if v.Unit == "%" && v.Max == 96 && len(v.OutlierHosts) > 0 && v.OutlierHosts[0] == "storage-08" {
			found96Outlier = true
		}
	}
	if !found96Outlier {
		t.Fatalf("expected 96%% outlier on storage-08, got variances: %+v", g1.Variances)
	}
	if len(g1.Hosts) != 2 || g1.Hosts[1] != "storage-08" {
		t.Fatalf("expected concise sample hosts to include typical + storage-08, got %v", g1.Hosts)
	}
}

func TestOpsSampleFreeMColumnAlignment(t *testing.T) {
	// Different column widths (16 GiB vs 256 GiB) must merge into a single cluster.
	h1 := "               total        used        free      shared  buff/cache   available\n" +
		"Mem:           15884        4123        8123         214        3637       11200\n" +
		"Swap:           4096           0        4096\n"
	h2 := "              total        used        free      shared  buff/cache   available\n" +
		"Mem:         257840       41230      181230        2140       35380      212000\n" +
		"Swap:          8192           0        8192\n"
	tasks := []TaskInput{
		makeSucceededTask("f1", "mem-01", h1, ""),
		makeSucceededTask("f2", "mem-02", h2, ""),
	}

	res := Cluster(tasks, ClusterOptions{Grouping: GroupingNormalized})
	assertHostConservation(t, tasks, res)

	if len(res.Groups) != 1 {
		t.Fatalf("expected free -m hosts with column width shift to merge into 1 cluster, got %d", len(res.Groups))
	}
	if len(res.Groups[0].Variances) == 0 {
		t.Fatalf("expected numeric variances for free -m")
	}
}

func TestOpsSampleUptime(t *testing.T) {
	tasks := make([]TaskInput, 0, 8)
	for i := 0; i < 8; i++ {
		load1 := 0.35 + float64(i%3)*0.05
		if i == 7 {
			load1 = 18.40
		}
		out := fmt.Sprintf(" 12:34:%02d up %d days, %2d:%02d,  1 user,  load average: %.2f, 0.38, 0.35\n",
			10+i, 10+i*5, 1+i, 15+i, load1)
		tasks = append(tasks, makeSucceededTask(fmt.Sprintf("u-%d", i), fmt.Sprintf("web-%02d", i), out, ""))
	}

	res := Cluster(tasks, ClusterOptions{Grouping: GroupingNormalized})
	assertHostConservation(t, tasks, res)
	if len(res.Groups) != 1 {
		t.Fatalf("expected 1 uptime cluster, got %d", len(res.Groups))
	}
	if res.Groups[0].Severity != SeverityAnomaly || res.Groups[0].AnomalyReason != ReasonMetricOutlier {
		t.Fatalf("expected metric_outlier on load average spike, got %+v", res.Groups[0])
	}
}

func TestOpsSampleDockerPSNDJSONOrderTruncationAndExited137(t *testing.T) {
	// Healthy hosts with identical containers in different order + one truncated at 4 KiB.
	c1 := `{"ID":"a1b2c3d4e5f6","Image":"nginx:1.25.3","Names":"gateway","Ports":"0.0.0.0:80->80/tcp, :::80->80/tcp","State":"running","Status":"Up 3 hours"}`
	c2 := `{"ID":"11223344aabb","Image":"redis:7.2.4","Names":"cache","Ports":"6379/tcp","State":"running","Status":"Up 5 days"}`

	c1b := `{"ID":"ff001122aabb","Image":"nginx:1.25.3","Names":"gateway","Ports":"0.0.0.0:80->80/tcp, :::80->80/tcp","State":"running","Status":"Up 42 minutes"}`
	c2b := `{"ID":"99887766ccdd","Image":"redis:7.2.4","Names":"cache","Ports":"6379/tcp","State":"running","Status":"Up 12 hours"}`

	// Host 3 has container exited with OOMKilled (137).
	c1oom := `{"ID":"dead00112233","Image":"nginx:1.25.3","Names":"gateway","Ports":"","State":"exited","Status":"Exited (137) 5 minutes ago"}`

	out1 := c1 + "\n" + c2 + "\n"
	out2 := c2b + "\n" + c1b + "\n" + `{"ID":"trunc_partial_line`
	out3 := c1oom + "\n" + c2b + "\n"

	t1 := makeSucceededTask("d1", "node-01", out1, "")
	t2 := makeSucceededTask("d2", "node-02", out2, "")
	t2.StdoutSize = uint64(len(out2) + 500) // simulate > 4 KiB truncation
	t3 := makeSucceededTask("d3", "node-03", out3, "")

	res := Cluster([]TaskInput{t1, t2, t3}, ClusterOptions{Grouping: GroupingNormalized})
	assertHostConservation(t, []TaskInput{t1, t2, t3}, res)

	if len(res.Groups) != 2 {
		t.Fatalf("expected 2 groups (2 healthy order/trunc-invariant + 1 Exited(137) minority), got %d: %+v", len(res.Groups), res.Groups)
	}
	if res.Groups[0].Severity != SeverityAnomaly || res.Groups[0].AnomalyReason != ReasonMinorityCluster || res.Groups[0].Hosts[0] != "node-03" {
		t.Fatalf("expected node-03 Exited(137) ranked first as minority_cluster, got %+v", res.Groups[0])
	}
	if !strings.Contains(res.Groups[0].TemplateStdout, "Exited (137)") {
		t.Fatalf("expected Exited (137) preserved in template: %s", res.Groups[0].TemplateStdout)
	}
	if res.Groups[1].Severity != SeverityNormal || res.Groups[1].HostCount != 2 {
		t.Fatalf("expected node-01 and node-02 merged in majority_normal, got %+v", res.Groups[1])
	}
}

func TestOpsSampleSystemctlStatus(t *testing.T) {
	mkHealthy := func(day, ts, up string, pid1, pid2 int, mem, cpu string) string {
		return fmt.Sprintf(
			"● nginx.service - A high performance web server\n"+
				"     Loaded: loaded (/lib/systemd/system/nginx.service; enabled)\n"+
				"     Active: active (running) since %s %s UTC; %s ago\n"+
				"   Main PID: %d (nginx)\n"+
				"      Tasks: 5 (limit: 19062)\n"+
				"     Memory: %s\n"+
				"        CPU: %s\n"+
				"     CGroup: /system.slice/nginx.service\n"+
				"             ├─%d \"nginx: master process /usr/sbin/nginx\"\n"+
				"             └─%d \"nginx: worker process\"\n",
			day, ts, up, pid1, mem, cpu, pid1, pid2,
		)
	}
	failedOut := "× nginx.service - A high performance web server\n" +
		"     Loaded: loaded (/lib/systemd/system/nginx.service; enabled)\n" +
		"     Active: failed (Result: exit-code) since Tue 2026-11-24 12:00:00 UTC; 3min ago\n" +
		"    Process: 4321 ExecStart=/usr/sbin/nginx (code=exited, status=1)\n"
	failedHash := sha256.Sum256([]byte(failedOut))
	emptyHash := sha256.Sum256(nil)

	tasks := []TaskInput{
		makeSucceededTask("s1", "web-01", mkHealthy("Mon", "2026-11-24 10:00:00", "2h 30min", 1234, 1235, "12.4M", "1.234s"), ""),
		makeSucceededTask("s2", "web-02", mkHealthy("Sun", "2026-11-23 08:15:00", "1 day 4h", 9876, 9877, "14.1M", "850ms"), ""),
		makeSucceededTask("s3", "web-03", mkHealthy("Mon", "2026-11-24 12:10:00", "15min", 5501, 5502, "11.9M", "2.100s"), ""),
		{
			HostID:     "s4",
			Hostname:   "web-04",
			Status:     StatusFailed,
			ExitCode:   i32(3),
			Reason:     "EXIT_NONZERO",
			Stdout:     []byte(failedOut),
			StdoutHash: failedHash[:],
			StderrHash: emptyHash[:],
			StdoutSize: uint64(len(failedOut)),
		},
	}

	res := Cluster(tasks, ClusterOptions{Grouping: GroupingNormalized})
	assertHostConservation(t, tasks, res)

	if len(res.Groups) != 2 {
		t.Fatalf("expected 2 groups (1 failed + 3 healthy merged), got %d: %+v", len(res.Groups), res.Groups)
	}
	if res.Groups[0].Severity != SeverityFailure || res.Groups[0].Hosts[0] != "web-04" {
		t.Fatalf("expected web-04 failed ranked #1, got %+v", res.Groups[0])
	}
	if res.Groups[1].Severity != SeverityNormal || res.Groups[1].HostCount != 3 {
		t.Fatalf("expected 3 healthy systemctl hosts merged, got %+v", res.Groups[1])
	}
}

func TestOpsSampleJVMPerfdataJSONAnd4KiBBoundary(t *testing.T) {
	// Part A: < 4 KiB JSON with Full GC outlier (MAD==0) and heap outlier.
	tasks := make([]TaskInput, 0, 10)
	for i := 0; i < 10; i++ {
		fullGC := 0
		heapMB := 512 + i*2
		if i == 9 {
			fullGC = 14
			heapMB = 3900
		}
		out := fmt.Sprintf(`{"host":"jvm-%02d.prod.local","ts":"2026-11-24T12:00:%02dZ","jvm_version":"17.0.9","heap_used_mb":%d,"heap_max_mb":4096,"full_gc_count":%d}`,
			i, i, heapMB, fullGC)
		tasks = append(tasks, makeSucceededTask(fmt.Sprintf("j-%02d", i), fmt.Sprintf("jvm-%02d.prod.local", i), out, ""))
	}
	res := Cluster(tasks, ClusterOptions{Grouping: GroupingNormalized})
	assertHostConservation(t, tasks, res)
	if len(res.Groups) != 1 {
		t.Fatalf("expected 1 merged JVM cluster, got %d", len(res.Groups))
	}
	if res.Groups[0].Severity != SeverityAnomaly || res.Groups[0].AnomalyReason != ReasonMetricOutlier {
		t.Fatalf("expected Tier 1 metric_outlier for JVM Full GC/heap spike, got %+v", res.Groups[0])
	}

	// Part B: 4 KiB boundary (pretty-printed JSON where 4 hosts are 3.9 KiB and 1 host is 4.1 KiB truncated).
	// Unified job-level mode must choose text for ALL hosts so identical lines don't split on JSON vs text.
	var baseLines strings.Builder
	baseLines.WriteString("{\n")
	for k := 0; k < 40; k++ {
		fmt.Fprintf(&baseLines, "  \"metric_%02d\": %d,\n", k, 100+k)
	}
	baseLines.WriteString("  \"status\": \"healthy\"\n}\n")
	fullBody := baseLines.String()

	// Make a slightly larger version that exceeds 4096 bytes and truncates cleanly at 4096.
	var bigLines strings.Builder
	bigLines.WriteString(strings.TrimSuffix(fullBody, "}\n"))
	bigLines.WriteString(",\n")
	for k := 40; k < 260; k++ {
		fmt.Fprintf(&bigLines, "  \"extra_metric_%03d\": %d,\n", k, k)
	}
	bigLines.WriteString("  \"end\": true\n}\n")
	bigFull := bigLines.String()
	bigPreview := bigFull[:MaxPreviewBytesPerStream]

	tFull := makeSucceededTask("b1", "jvm-a", fullBody, "")
	tTrunc := makeSucceededTask("b2", "jvm-b", bigPreview, "")
	tTrunc.StdoutSize = uint64(len(bigFull))

	mode := DetectStreamMode([]PreviewSample{
		{Data: tFull.Stdout, TotalSize: tFull.StdoutSize},
		{Data: tTrunc.Stdout, TotalSize: tTrunc.StdoutSize},
	})
	if mode != PreviewModeText {
		t.Fatalf("expected PreviewModeText across 4 KiB JSON boundary, got %q", mode)
	}
}

func TestOpsSampleLogQueryJSONHitCountsAndNewExceptionStack(t *testing.T) {
	tasks := make([]TaskInput, 0, 6)
	for i := 0; i < 5; i++ {
		var recs []string
		for r := 0; r <= i; r++ {
			recs = append(recs, fmt.Sprintf(`{"ts":"2026-11-24T12:0%d:00Z","level":"WARN","msg":"upstream retry after %dms"}`, r, 100+r*20))
		}
		out := fmt.Sprintf(`{"query":"retry","records":[%s]}`, strings.Join(recs, ","))
		tasks = append(tasks, makeSucceededTask(fmt.Sprintf("l-%d", i), fmt.Sprintf("api-%02d", i), out, ""))
	}
	// Host 5 has a brand-new NullPointerException stack trace!
	excOut := `{"query":"retry","records":[{"ts":"2026-11-24T12:05:00Z","level":"ERROR","msg":"java.lang.NullPointerException: order is null\n\tat com.example.OrderSvc.pay(OrderSvc.java:88)"}]}`
	tasks = append(tasks, makeSucceededTask("l-5", "api-05", excOut, ""))

	res := Cluster(tasks, ClusterOptions{Grouping: GroupingNormalized})
	assertHostConservation(t, tasks, res)

	if len(res.Groups) != 2 {
		t.Fatalf("expected 2 groups (1 new exception minority + 5 varying hit-count normal), got %d: %+v", len(res.Groups), res.Groups)
	}
	if res.Groups[0].Severity != SeverityAnomaly || res.Groups[0].AnomalyReason != ReasonMinorityCluster || res.Groups[0].Hosts[0] != "api-05" {
		t.Fatalf("expected api-05 exception ranked first as minority_cluster, got %+v", res.Groups[0])
	}
	if res.Groups[1].HostCount != 5 {
		t.Fatalf("expected 5 varying hit-count hosts merged, got %d", res.Groups[1].HostCount)
	}
	foundLenVar := false
	for _, v := range res.Groups[1].Variances {
		if v.Label == "records.$len" && v.Min == 1 && v.Max == 5 {
			foundLenVar = true
		}
	}
	if !foundLenVar {
		t.Fatalf("expected records.$len variance [1..5], got %+v", res.Groups[1].Variances)
	}
}

func TestOpsSampleVersionUpgradeAndHTTPStatusCodes(t *testing.T) {
	base := []TaskInput{
		makeSucceededTask("v1", "edge-01", "Server: nginx/1.24.0\nHTTP/1.1 200 OK\n", ""),
		makeSucceededTask("v2", "edge-02", "Server: nginx/1.24.0\nHTTP/1.1 200 OK\n", ""),
	}
	target := []TaskInput{
		makeSucceededTask("v1", "edge-01", "Server: nginx/1.25.3\nHTTP/1.1 200 OK\n", ""),
		makeSucceededTask("v2", "edge-02", "Server: nginx/1.25.3\nHTTP/1.1 500 Internal Server Error\n", ""),
	}

	clRes := Cluster(target, ClusterOptions{Grouping: GroupingNormalized})
	assertHostConservation(t, target, clRes)
	if len(clRes.Groups) != 2 {
		t.Fatalf("expected HTTP 200 vs 500 to stay in 2 separate clusters, got %d", len(clRes.Groups))
	}

	diffRes := Diff(base, target, DefaultDiffOptions())
	if diffRes.TotalPatternChanges != 2 {
		t.Fatalf("expected 2 distinct pattern changes (1.24->1.25 200 and 1.24->1.25 500), got %d: %+v",
			diffRes.TotalPatternChanges, diffRes.PatternChanges)
	}
	foundNginxDiff := false
	for _, pc := range diffRes.PatternChanges {
		for _, a := range pc.AddedLines {
			if strings.Contains(a, "nginx/1.25.3") {
				foundNginxDiff = true
			}
		}
	}
	if !foundNginxDiff {
		t.Fatalf("expected nginx/1.25.3 in diff AddedLines, got %+v", diffRes.PatternChanges)
	}
}

func TestAdversarialEndToEndInvariants(t *testing.T) {
	// Combine invalid UTF-8, NUL bytes, 4 KiB single line with no newline, depth-50 JSON,
	// 1e999/NaN strings, [REDACTED:secrets], and verify determinism + finite float + UTF-8 invariants.
	badBytes := append([]byte("host=evil-01 [REDACTED:secrets] x=1e999 y=NaN \x00\xff\xfe"), bytes.Repeat([]byte("A"), 4096)...)
	deepJSON := strings.Repeat(`{"n":`, 50) + "1" + strings.Repeat("}", 50)

	tasks := []TaskInput{
		makeSucceededTask("e1", "evil-01", string(badBytes), ""),
		makeSucceededTask("e2", "evil-02", deepJSON, ""),
		makeSucceededTask("e3", "evil-03", `{"a":1e999,"b":-1e999,"c":12}`, ""),
		makeSucceededTask("e4", "evil-04", `{"a":1e999,"b":-1e999,"c":24}`, ""),
	}

	r1 := Cluster(tasks, ClusterOptions{Grouping: GroupingNormalized})
	r2 := Cluster(tasks, ClusterOptions{Grouping: GroupingNormalized})
	assertHostConservation(t, tasks, r1)
	if !reflect.DeepEqual(r1, r2) {
		t.Fatalf("repeated Cluster calls were not byte-identical")
	}
	for _, g := range r1.Groups {
		if !utf8.ValidString(g.Stdout) || !utf8.ValidString(g.TemplateStdout) {
			t.Fatalf("invalid UTF-8 in group output: %+v", g)
		}
		if g.Hosts[0] == "evil-01" && !strings.Contains(g.TemplateStdout, "[REDACTED:secrets]") {
			t.Fatalf("[REDACTED:secrets] was corrupted in template: %q", g.TemplateStdout)
		}
		for _, v := range g.Variances {
			if math.IsNaN(v.Min) || math.IsInf(v.Min, 0) || math.IsNaN(v.P50) || math.IsInf(v.P50, 0) ||
				math.IsNaN(v.P95) || math.IsInf(v.P95, 0) || math.IsNaN(v.Max) || math.IsInf(v.Max, 0) {
				t.Fatalf("non-finite variance: %+v", v)
			}
		}
	}

	d1 := Diff(tasks, tasks, DefaultDiffOptions())
	d2 := Diff(tasks, tasks, DefaultDiffOptions())
	if !reflect.DeepEqual(d1, d2) {
		t.Fatalf("repeated Diff calls were not deterministic")
	}
}

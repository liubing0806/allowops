package cluster

import (
	"crypto/sha256"
	"fmt"
	"math"
	"reflect"
	"testing"
)

func i32(v int32) *int32 { return &v }

func makeSucceededTask(id, host, stdout, stderr string) TaskInput {
	oh := sha256.Sum256([]byte(stdout))
	eh := sha256.Sum256([]byte(stderr))
	return TaskInput{
		HostID:     id,
		Hostname:   host,
		Status:     StatusSucceeded,
		ExitCode:   i32(0),
		Stdout:     []byte(stdout),
		Stderr:     []byte(stderr),
		StdoutHash: oh[:],
		StderrHash: eh[:],
		StdoutSize: uint64(len(stdout)),
		StderrSize: uint64(len(stderr)),
	}
}

func assertHostConservation(t *testing.T, tasks []TaskInput, res ClusterResult) {
	t.Helper()
	var sum uint64
	for _, g := range res.Groups {
		sum += g.HostCount
		for _, v := range g.Variances {
			if !isFiniteFloat(v.Min) || !isFiniteFloat(v.P50) || !isFiniteFloat(v.P95) || !isFiniteFloat(v.Max) {
				t.Fatalf("non-finite variance in group %q: %+v", g.AnomalyReason, v)
			}
			assertCleanLabel(t, v.Label)
			assertCleanLabel(t, v.Unit)
		}
	}
	got := sum + uint64(len(res.OfflineHosts)) + res.UnfinishedHostsCount
	if got != uint64(len(tasks)) || res.TotalTasks != uint64(len(tasks)) {
		t.Fatalf("host conservation violated: groups=%d + offline=%d + unfinished=%d = %d != len(tasks)=%d",
			sum, len(res.OfflineHosts), res.UnfinishedHostsCount, got, len(tasks))
	}
}

func TestClusterTier0AllFailureClassesAndHostConservation(t *testing.T) {
	tasks := []TaskInput{
		makeSucceededTask("h1", "web-01", "ok\n", ""),
		makeSucceededTask("h2", "web-02", "ok\n", ""),
		makeSucceededTask("h3", "web-03", "ok\n", "warning: deprecated\n"),
		makeSucceededTask("h4", "web-04", "different\n", ""),
		{HostID: "h5", Hostname: "web-05", Status: StatusOffline},
		{HostID: "h6", Hostname: "web-06", Status: StatusPending},
		{HostID: "h7", Hostname: "web-07", Status: StatusRunning},
		{HostID: "h8", Hostname: "web-08", Status: StatusTimeout, Reason: "TIMEOUT"},
		{HostID: "h9", Hostname: "web-09", Status: StatusFailed, ExitCode: i32(1), Reason: "EXIT_NONZERO"},
		{HostID: "h10", Hostname: "web-10", Status: StatusUnsupported, Reason: "CATALOG_REJECTED"},
		{HostID: "h11", Hostname: "web-11", Status: StatusCancelled, Reason: "CANCELLED"},
		{HostID: "h12", Hostname: "web-12", Status: StatusSkipped, Reason: "MAX_FAILURES"},
		{HostID: "h13", Hostname: "web-13", Status: StatusFailed, Reason: "DISPATCH_CAPACITY"},
	}

	for _, mode := range []GroupingMode{GroupingExact, GroupingNormalized} {
		res := Cluster(tasks, ClusterOptions{Grouping: mode})
		assertHostConservation(t, tasks, res)

		if len(res.OfflineHosts) != 1 || res.OfflineHosts[0] != "web-05" {
			t.Fatalf("[%s] unexpected offline hosts: %v", mode, res.OfflineHosts)
		}
		if res.UnfinishedHostsCount != 2 {
			t.Fatalf("[%s] expected 2 unfinished hosts, got %d", mode, res.UnfinishedHostsCount)
		}

		// Verify strict tier & sub-rank ordering:
		// 0: timeout, 1: nonzero_exit / task_failed, 2: task_unsupported, 3: task_cancelled, 4: task_skipped,
		// then Tier 1: stderr_present, minority_cluster, then Tier 2: majority_normal.
		wantReasons := []string{
			ReasonTimeout,
			ReasonTaskFailed, // DISPATCH_CAPACITY (reason ASC: "DISPATCH_CAPACITY" < "EXIT_NONZERO")
			ReasonNonZeroExit,
			ReasonTaskUnsupported,
			ReasonTaskCancelled,
			ReasonTaskSkipped,
			ReasonStderrPresent,
			ReasonMinorityCluster,
			ReasonMajorityNormal,
		}
		if len(res.Groups) != len(wantReasons) {
			t.Fatalf("[%s] got %d groups, want %d: %+v", mode, len(res.Groups), len(wantReasons), res.Groups)
		}
		for i, want := range wantReasons {
			if res.Groups[i].AnomalyReason != want {
				t.Errorf("[%s] group[%d].AnomalyReason = %q, want %q", mode, i, res.Groups[i].AnomalyReason, want)
			}
		}
	}
}

func TestClusterOverflowNeverDropsTailFailureTask(t *testing.T) {
	// 1000 high-entropy succeeded hosts + 1 timeout task at position 999 (last index).
	tasks := make([]TaskInput, 0, 1001)
	for i := 0; i < 1000; i++ {
		out := fmt.Sprintf("unique_word_%s_payload_%d\n", alphaTag(i), i)
		tasks = append(tasks, makeSucceededTask(fmt.Sprintf("id-%04d", i), fmt.Sprintf("host-%04d", i), out, ""))
	}
	// Put a timeout task at the very tail (index 1000).
	tasks = append(tasks, TaskInput{
		HostID:   "id-tail-timeout",
		Hostname: "z-tail-timeout",
		Status:   StatusTimeout,
		Reason:   "TIMEOUT",
	})

	res := Cluster(tasks, ClusterOptions{Grouping: GroupingNormalized})
	assertHostConservation(t, tasks, res)

	if !res.Truncated {
		t.Fatalf("expected Truncated=true due to MaxClusters overflow")
	}
	if len(res.Groups) == 0 {
		t.Fatalf("expected non-empty groups")
	}
	// Position 999+ timeout task MUST rank #1!
	if res.Groups[0].Severity != SeverityFailure || res.Groups[0].AnomalyReason != ReasonTimeout {
		t.Fatalf("expected timeout group ranked #1, got severity=%v reason=%q", res.Groups[0].Severity, res.Groups[0].AnomalyReason)
	}
	if res.Groups[0].Hosts[0] != "z-tail-timeout" {
		t.Fatalf("expected z-tail-timeout in group 0, got %v", res.Groups[0].Hosts)
	}

	// Verify explicit overflow bucket exists at the end of Tier 2 with exact remaining host count.
	last := res.Groups[len(res.Groups)-1]
	if last.Severity != SeverityNormal || last.AnomalyReason != ReasonClusterLimitOverflow {
		t.Fatalf("expected last group to be cluster_limit_overflow, got %+v", last)
	}
	if last.HostCount != uint64(1000-MaxClusters) {
		t.Fatalf("expected overflow host count=%d, got %d", 1000-MaxClusters, last.HostCount)
	}
}

func alphaTag(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := [4]byte{
		letters[(n/(26*26*26))%26],
		letters[(n/(26*26))%26],
		letters[(n/26)%26],
		letters[n%26],
	}
	return string(b[:])
}

func TestClusterMADZeroOutlierAndConciseSmartSample(t *testing.T) {
	// 19 hosts with full_gc=0, 1 host with full_gc=1 (MAD == 0 case!).
	tasks := make([]TaskInput, 0, 20)
	for i := 0; i < 20; i++ {
		gc := 0
		if i == 17 {
			gc = 1
		}
		out := fmt.Sprintf(`{"full_gc": %d, "heap_mb": %d}`, gc, 500+i%3)
		tasks = append(tasks, makeSucceededTask(fmt.Sprintf("id-%02d", i), fmt.Sprintf("app-%02d", i), out, ""))
	}

	res := Cluster(tasks, ClusterOptions{Grouping: GroupingNormalized, Detailed: false})
	assertHostConservation(t, tasks, res)

	if len(res.Groups) != 1 {
		t.Fatalf("expected 1 normalized cluster, got %d", len(res.Groups))
	}
	g := res.Groups[0]
	if g.Severity != SeverityAnomaly || g.AnomalyReason != ReasonMetricOutlier {
		t.Fatalf("expected Tier 1 metric_outlier, got severity=%v reason=%q", g.Severity, g.AnomalyReason)
	}
	if len(g.TemplateHash) != 32 || g.StdoutHash != nil || g.StderrHash != nil {
		t.Fatalf("normalized group must populate only TemplateHash, got tmpl=%d out=%d err=%d",
			len(g.TemplateHash), len(g.StdoutHash), len(g.StderrHash))
	}
	if len(g.Variances) == 0 || g.Variances[0].Label != "full_gc" {
		t.Fatalf("expected full_gc top variance, got %+v", g.Variances)
	}
	v := g.Variances[0]
	if v.Min != 0 || v.P50 != 0 || v.Max != 1 || len(v.OutlierHosts) != 1 || v.OutlierHosts[0] != "app-17" {
		t.Fatalf("unexpected full_gc variance: %+v", v)
	}
	// Concise sample hosts MUST include 1 typical host + 1 extreme outlier host ("app-17").
	if len(g.Hosts) != 2 || g.Hosts[1] != "app-17" {
		t.Fatalf("expected concise hosts=[typical, app-17], got %v", g.Hosts)
	}
}

func TestClusterMaxTasksFallbackAndDeterminism(t *testing.T) {
	// Test > MaxTasks deterministic fallback to exact.
	tasks := make([]TaskInput, MaxTasks+1)
	for i := range tasks {
		tasks[i] = makeSucceededTask(fmt.Sprintf("id-%05d", i), fmt.Sprintf("h-%05d", i), "steady output\n", "")
	}
	res := Cluster(tasks, ClusterOptions{Grouping: GroupingNormalized})
	assertHostConservation(t, tasks, res)
	if res.Grouping != GroupingExact || !res.Truncated {
		t.Fatalf("expected fallback to exact with Truncated=true, got grouping=%q truncated=%v", res.Grouping, res.Truncated)
	}

	// Test byte-identical determinism across repeated runs with shuffled input order.
	subset := []TaskInput{
		makeSucceededTask("3", "h3", "cpu=95% mem=800MiB\n", ""),
		makeSucceededTask("1", "h1", "cpu=20% mem=500MiB\n", ""),
		makeSucceededTask("4", "h4", "cpu=22% mem=510MiB\n", ""),
		makeSucceededTask("2", "h2", "cpu=21% mem=505MiB\n", ""),
		makeSucceededTask("5", "h5", "cpu=19% mem=498MiB\n", ""),
		makeSucceededTask("6", "h6", "cpu=20% mem=502MiB\n", ""),
		{HostID: "7", Hostname: "h7", Status: StatusOffline},
		{HostID: "8", Hostname: "h8", Status: StatusTimeout, Reason: "TIMEOUT"},
	}
	first := Cluster(subset, ClusterOptions{Grouping: GroupingNormalized})
	// Reversed order must produce deeply identical result!
	reversed := make([]TaskInput, len(subset))
	for i := range subset {
		reversed[i] = subset[len(subset)-1-i]
	}
	second := Cluster(reversed, ClusterOptions{Grouping: GroupingNormalized})
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("clustering must be deterministic regardless of input order:\nfirst =%+v\nsecond=%+v", first, second)
	}
}

func TestStatsRelDiffZeroMedianSafe(t *testing.T) {
	d := relDiff(5, 0)
	if math.IsNaN(d) || math.IsInf(d, 0) || d != 5 {
		t.Fatalf("expected relDiff(5, 0) = 5, got %v", d)
	}
}

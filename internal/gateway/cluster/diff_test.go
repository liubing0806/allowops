package cluster

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestDiffHostIDAlignmentAndReplacedHosts(t *testing.T) {
	base := []TaskInput{
		makeSucceededTask("id-1", "web-01", "v1.0.0\n", ""),
		makeSucceededTask("id-old-2", "web-02", "v1.0.0\n", ""),
		makeSucceededTask("id-removed", "web-03", "v1.0.0\n", ""),
	}
	target := []TaskInput{
		makeSucceededTask("id-1", "web-01", "v1.0.0\n", ""),
		makeSucceededTask("id-new-2", "web-02", "v2.0.0\n", ""), // same hostname, DIFFERENT HostID!
		makeSucceededTask("id-added", "web-04", "v1.0.0\n", ""),
	}

	res := Diff(base, target, DefaultDiffOptions())
	if res.UnchangedHostsCount != 1 {
		t.Fatalf("expected 1 unchanged host (id-1), got %d", res.UnchangedHostsCount)
	}
	if len(res.RemovedHosts) != 2 || res.RemovedHosts[0] != "web-02" || res.RemovedHosts[1] != "web-03" {
		t.Fatalf("unexpected removed hosts: %v", res.RemovedHosts)
	}
	if len(res.AddedHosts) != 2 || res.AddedHosts[0] != "web-02" || res.AddedHosts[1] != "web-04" {
		t.Fatalf("unexpected added hosts: %v", res.AddedHosts)
	}
	if len(res.ReplacedHosts) != 1 || res.ReplacedHosts[0] != "web-02" || res.ReplacedHostsCount != 1 {
		t.Fatalf("expected ReplacedHosts=[web-02], got %v (count=%d)", res.ReplacedHosts, res.ReplacedHostsCount)
	}
	// web-02 must NOT have been paired into PatternChanges!
	if len(res.PatternChanges) != 0 {
		t.Fatalf("replaced host must not be compared as same host, got pattern changes: %+v", res.PatternChanges)
	}
}

func TestDiffIdempotentBaseEqualsTarget(t *testing.T) {
	tasks := []TaskInput{
		makeSucceededTask("h1", "web-01", `{"heap": 1024, "full_gc": 0}`, ""),
		makeSucceededTask("h2", "web-02", `{"heap": 2048, "full_gc": 0}`, ""),
		{HostID: "h3", Hostname: "web-03", Status: StatusOffline},
	}

	res := Diff(tasks, tasks, DefaultDiffOptions())
	if res.UnchangedHostsCount != 3 {
		t.Fatalf("expected UnchangedHostsCount=3, got %d", res.UnchangedHostsCount)
	}
	if len(res.AddedHosts) != 0 || len(res.RemovedHosts) != 0 || len(res.ReplacedHosts) != 0 {
		t.Fatalf("expected zero host changes, got added=%v removed=%v replaced=%v", res.AddedHosts, res.RemovedHosts, res.ReplacedHosts)
	}
	if len(res.StatusTransitions) != 0 || len(res.PatternChanges) != 0 || len(res.MetricDrifts) != 0 {
		t.Fatalf("expected zero diff on base==target, got transitions=%+v patterns=%+v drifts=%+v",
			res.StatusTransitions, res.PatternChanges, res.MetricDrifts)
	}

	// OnlyChanged=false appends unchanged pattern groups.
	optsAll := DefaultDiffOptions()
	optsAll.OnlyChanged = false
	resAll := Diff(tasks, tasks, optsAll)
	if resAll.TotalPatternChanges != 0 {
		t.Fatalf("expected TotalPatternChanges=0, got %d", resAll.TotalPatternChanges)
	}
	if len(resAll.PatternChanges) != 2 {
		t.Fatalf("expected 2 unchanged pattern groups (succeeded + offline), got %d", len(resAll.PatternChanges))
	}
	for _, pc := range resAll.PatternChanges {
		if !pc.Unchanged {
			t.Fatalf("expected Unchanged=true on all entries: %+v", pc)
		}
	}
}

func TestDiffStatusTransitionsDegradationFirst(t *testing.T) {
	base := []TaskInput{
		{HostID: "h1", Hostname: "h1", Status: StatusFailed, ExitCode: i32(1), Reason: "EXIT_NONZERO"}, // recovers
		makeSucceededTask("h2", "h2", "ok\n", ""),                                                      // degrades to timeout
		makeSucceededTask("h3", "h3", "ok\n", ""),                                                      // degrades to offline
		{HostID: "h4", Hostname: "h4", Status: StatusOffline},                                          // anomaly-to-anomaly (offline -> failed)
	}
	target := []TaskInput{
		makeSucceededTask("h1", "h1", "ok\n", ""),
		{HostID: "h2", Hostname: "h2", Status: StatusTimeout, Reason: "TIMEOUT"},
		{HostID: "h3", Hostname: "h3", Status: StatusOffline},
		{HostID: "h4", Hostname: "h4", Status: StatusFailed, ExitCode: i32(2), Reason: "EXIT_NONZERO"},
	}

	res := Diff(base, target, DefaultDiffOptions())
	if len(res.StatusTransitions) != 4 {
		t.Fatalf("expected 4 transitions, got %d: %+v", len(res.StatusTransitions), res.StatusTransitions)
	}
	// Order: degradation timeout -> degradation offline -> anomaly-to-anomaly -> recovery.
	if !res.StatusTransitions[0].Degradation || res.StatusTransitions[0].ToStatus != StatusTimeout {
		t.Fatalf("expected timeout degradation first, got %+v", res.StatusTransitions[0])
	}
	if !res.StatusTransitions[1].Degradation || res.StatusTransitions[1].ToStatus != StatusOffline {
		t.Fatalf("expected offline degradation second, got %+v", res.StatusTransitions[1])
	}
	if res.StatusTransitions[2].Degradation || res.StatusTransitions[2].FromStatus != StatusOffline {
		t.Fatalf("expected anomaly-to-anomaly third, got %+v", res.StatusTransitions[2])
	}
	if res.StatusTransitions[3].Degradation || res.StatusTransitions[3].ToStatus != StatusSucceeded {
		t.Fatalf("expected recovery last, got %+v", res.StatusTransitions[3])
	}
}

func TestDiffTopKBoundedLineDiffAndLineCaps(t *testing.T) {
	// Create 40 distinct changed patterns (> MaxDetailedPatternDiffs = 32) and verify:
	// - TotalPatternChanges == 40
	// - Exactly first 32 have DiffComputed == true
	// - Entries 32..39 have DiffComputed == false and nil RemovedLines/AddedLines
	// - Line diff caps removed/added to MaxDiffLinesPerEntry (6) and MaxDiffLineBytes (256).
	base := make([]TaskInput, 0, 40)
	target := make([]TaskInput, 0, 40)
	longSuffix := strings.Repeat("x", 400)
	for i := 0; i < 40; i++ {
		var bOut, tOut strings.Builder
		bOut.WriteString("common-header\n")
		tOut.WriteString("common-header\n")
		for line := 0; line < 10; line++ {
			fmt.Fprintf(&bOut, "old_%s_line_%d_%s\n", alphaTag(i), line, longSuffix)
			fmt.Fprintf(&tOut, "new_%s_line_%d_%s\n", alphaTag(i), line, longSuffix)
		}
		bOut.WriteString("common-footer\n")
		tOut.WriteString("common-footer\n")

		id := fmt.Sprintf("id-%02d", i)
		host := fmt.Sprintf("host-%02d", i)
		base = append(base, makeSucceededTask(id, host, bOut.String(), ""))
		target = append(target, makeSucceededTask(id, host, tOut.String(), ""))
	}

	res := Diff(base, target, DefaultDiffOptions())
	if res.TotalPatternChanges != 40 {
		t.Fatalf("expected TotalPatternChanges=40, got %d", res.TotalPatternChanges)
	}
	for i, pc := range res.PatternChanges {
		if i < MaxDetailedPatternDiffs {
			if !pc.DiffComputed {
				t.Fatalf("pattern[%d] should have DiffComputed=true", i)
			}
			if len(pc.RemovedLines) != MaxDiffLinesPerEntry || len(pc.AddedLines) != MaxDiffLinesPerEntry {
				t.Fatalf("pattern[%d] expected 6 removed and 6 added lines, got %d/%d", i, len(pc.RemovedLines), len(pc.AddedLines))
			}
			for _, l := range append(pc.RemovedLines, pc.AddedLines...) {
				if len(l) > MaxDiffLineBytes {
					t.Fatalf("diff line exceeded MaxDiffLineBytes (%d > %d)", len(l), MaxDiffLineBytes)
				}
			}
		} else {
			if pc.DiffComputed || len(pc.RemovedLines) != 0 || len(pc.AddedLines) != 0 {
				t.Fatalf("pattern[%d] beyond top %d must not compute line diff", i, MaxDetailedPatternDiffs)
			}
		}
	}
}

func TestDiffMetricDriftZeroBaseNilPctAndFiniteInvariant(t *testing.T) {
	base := []TaskInput{
		makeSucceededTask("h1", "app-01", `{"full_gc": 0, "disk_pct": "40%", "heap_mb": 1000, "huge": 1e999}`, ""),
		makeSucceededTask("h2", "app-02", `{"full_gc": 0, "disk_pct": "42%", "heap_mb": 1020, "huge": 1e999}`, ""),
	}
	target := []TaskInput{
		makeSucceededTask("h1", "app-01", `{"full_gc": 5, "disk_pct": "95%", "heap_mb": 1500, "huge": 1e999}`, ""),
		makeSucceededTask("h2", "app-02", `{"full_gc": 0, "disk_pct": "43%", "heap_mb": 1030, "huge": 1e999}`, ""),
	}

	res := Diff(base, target, DefaultDiffOptions())
	if len(res.MetricDrifts) != 3 {
		t.Fatalf("expected 3 significant drifts (full_gc, disk_pct, heap_mb), got %d: %+v", len(res.MetricDrifts), res.MetricDrifts)
	}

	byLabel := make(map[string]MetricDrift)
	for _, d := range res.MetricDrifts {
		byLabel[d.Label] = d
		if !isFiniteFloat(d.BaseP50) || !isFiniteFloat(d.TargetP50) || !isFiniteFloat(d.MaxDelta) {
			t.Fatalf("non-finite drift value: %+v", d)
		}
		if d.MaxDeltaPct != nil && (math.IsNaN(*d.MaxDeltaPct) || math.IsInf(*d.MaxDeltaPct, 0)) {
			t.Fatalf("non-finite MaxDeltaPct: %+v", d)
		}
	}

	// full_gc had base=0 -> MaxDeltaPct MUST be nil!
	gc, ok := byLabel["full_gc"]
	if !ok {
		t.Fatalf("missing full_gc drift")
	}
	if gc.MaxDeltaPct != nil {
		t.Fatalf("expected MaxDeltaPct=nil when base==0, got %v", *gc.MaxDeltaPct)
	}
	if gc.MaxDelta != 5 || gc.MaxHost != "app-01" {
		t.Fatalf("unexpected full_gc drift: %+v", gc)
	}

	// heap_mb went 1000 -> 1500 (+50%).
	heap, ok := byLabel["heap_mb"]
	if !ok || heap.MaxDeltaPct == nil || math.Abs(*heap.MaxDeltaPct-50.0) > 1e-9 {
		t.Fatalf("unexpected heap_mb drift: %+v", heap)
	}
}

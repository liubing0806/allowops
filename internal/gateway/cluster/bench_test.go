package cluster

import (
	"fmt"
	"strings"
	"testing"
)

func buildRealisticOpsPreview(hostIdx int) string {
	var b strings.Builder
	b.Grow(MaxPreviewBytesPerStream)
	fmt.Fprintf(&b, "Host: prod-app-%04d.us-east.internal  Time: 2026-11-24T12:34:%02dZ\n", hostIdx, hostIdx%60)
	fmt.Fprintf(&b, " 12:34:%02d up %d days,  3:15,  1 user,  load average: %.2f, %.2f, %.2f\n",
		hostIdx%60, 10+hostIdx%90, 0.40+float64(hostIdx%10)*0.05, 0.38, 0.35)
	fmt.Fprintf(&b, "Server: nginx/1.25.3 HTTP/1.1 200 OK pid=%d req=550e8400-e29b-41d4-a716-44665544%04x ip=10.20.%d.%d:8080\n",
		1000+hostIdx, hostIdx&0xffff, (hostIdx/250)%255, hostIdx%250+1)
	b.WriteString("Filesystem      Size  Used Avail Use% Mounted on\n")
	for m := 0; m < 45; m++ {
		pct := 35 + (hostIdx+m)%15
		if hostIdx == 997 && m == 0 {
			pct = 97
		}
		fmt.Fprintf(&b, "/dev/nvme0n1p%d  200G  %3dG  %3dG  %2d%% /data/vol%02d\n",
			m+1, 70+m%30, 130-m%30, pct, m)
	}
	s := b.String()
	if len(s) > MaxPreviewBytesPerStream {
		s = s[:MaxPreviewBytesPerStream]
	}
	return s
}

func BenchmarkNormalizePreview(b *testing.B) {
	raw := []byte(buildRealisticOpsPreview(42))
	opts := DefaultNormalizeOptions("prod-app-0042.us-east.internal")
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := NormalizePreview(raw, opts)
		if res.Template == "" {
			b.Fatal("empty template")
		}
	}
}

func BenchmarkCluster1000Hosts(b *testing.B) {
	tasks := make([]TaskInput, 1000)
	for i := 0; i < 1000; i++ {
		out := buildRealisticOpsPreview(i)
		tasks[i] = makeSucceededTask(fmt.Sprintf("id-%04d", i), fmt.Sprintf("prod-app-%04d.us-east.internal", i), out, "")
	}
	// Inject 5 failures and 3 offline hosts to exercise both passes.
	for i := 0; i < 5; i++ {
		tasks[990+i] = TaskInput{
			HostID:   fmt.Sprintf("id-%04d", 990+i),
			Hostname: fmt.Sprintf("prod-app-%04d.us-east.internal", 990+i),
			Status:   StatusTimeout,
			Reason:   "TIMEOUT",
		}
	}
	for i := 0; i < 3; i++ {
		tasks[995+i] = TaskInput{
			HostID:   fmt.Sprintf("id-%04d", 995+i),
			Hostname: fmt.Sprintf("prod-app-%04d.us-east.internal", 995+i),
			Status:   StatusOffline,
		}
	}

	opts := ClusterOptions{Grouping: GroupingNormalized}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := Cluster(tasks, opts)
		if res.TotalTasks != 1000 {
			b.Fatalf("unexpected TotalTasks=%d", res.TotalTasks)
		}
	}
}

func BenchmarkDiff1000Hosts(b *testing.B) {
	base := make([]TaskInput, 1000)
	target := make([]TaskInput, 1000)
	for i := 0; i < 1000; i++ {
		id := fmt.Sprintf("id-%04d", i)
		host := fmt.Sprintf("prod-app-%04d.us-east.internal", i)
		baseOut := buildRealisticOpsPreview(i)
		base[i] = makeSucceededTask(id, host, baseOut, "")

		targetOut := baseOut
		if i < 20 {
			targetOut = strings.Replace(baseOut, "nginx/1.25.3", "nginx/1.26.0", 1)
		}
		if i == 999 {
			target[i] = TaskInput{HostID: id, Hostname: host, Status: StatusTimeout, Reason: "TIMEOUT"}
		} else {
			target[i] = makeSucceededTask(id, host, targetOut, "")
		}
	}

	opts := DefaultDiffOptions()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := Diff(base, target, opts)
		if res.TotalPatternChanges == 0 {
			b.Fatal("expected non-zero pattern changes")
		}
	}
}

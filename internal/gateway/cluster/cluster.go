package cluster

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
)

// TaskInput is the pure, proto-independent representation of a task preview
// consumed by Cluster and Diff.
type TaskInput struct {
	HostID          string
	Hostname        string
	Status          TaskStatus
	ExitCode        *int32
	Reason          string
	ResultTruncated bool
	Stdout          []byte
	Stderr          []byte
	StdoutHash      []byte
	StderrHash      []byte
	StdoutSize      uint64
	StderrSize      uint64
}

// ClusterOptions configures two-pass deterministic clustering and ranking.
type ClusterOptions struct {
	// Grouping selects GroupingExact (default when empty) or GroupingNormalized.
	Grouping GroupingMode
	// Detailed includes every hostname in each group when true; false limits
	// sample hosts to ConciseSampleHosts (2), preferring 1 typical + 1 outlier.
	Detailed bool
	// MaskIPs controls IP normalization in normalized mode. Nil defaults to true.
	MaskIPs *bool
}

// Group represents a clustered group of host outputs.
type Group struct {
	Severity       Severity
	SeveritySub    uint8
	AnomalyReason  string
	Status         TaskStatus
	ExitCode       *int32
	Reason         string
	StdoutHash     []byte // populated in exact mode when present; nil in normalized mode
	StderrHash     []byte // populated in exact mode when present; nil in normalized mode
	TemplateHash   []byte // populated in normalized mode; nil in exact mode
	HostCount      uint64
	Hosts          []string
	Stdout         string
	Stderr         string
	TemplateStdout string // omitted when equal to Stdout
	TemplateStderr string // omitted when equal to Stderr
	Truncated      bool
	Variances      []MetricVariance
}

// ClusterResult holds the deterministic clustering and ranking output along
// with exact conservation counts.
//
// Host Conservation Invariant:
//
//	sum(g.HostCount for g in Groups) + uint64(len(OfflineHosts)) + UnfinishedHostsCount == TotalTasks
type ClusterResult struct {
	Groups               []Group
	OfflineHosts         []string
	UnfinishedHostsCount uint64
	Grouping             GroupingMode
	Ranking              string
	TotalGroups          uint64
	FoldedNormalHosts    uint64
	Truncated            bool
	TotalTasks           uint64
}

// Cluster executes two-pass deterministic clustering and unified Anomaly-First
// ranking over tasks.
//
// Pass 1 classifies offline hosts, unfinished tasks, and unconditionally
// collects all failure / non-succeeded / non-zero / reason-bearing /
// missing-hash terminal tasks into Tier 0 (never squeezed out by Pass 2's
// MaxClusters ceiling).
//
// Pass 2 clusters clean succeeded tasks (exact or normalized), computes numeric
// distributions and MAD outliers, selects smart concise sample hosts, and
// applies unified Anomaly-First ranking.
func Cluster(tasks []TaskInput, opts ClusterOptions) ClusterResult {
	effectiveGrouping := opts.Grouping
	if effectiveGrouping == "" {
		effectiveGrouping = GroupingExact
	}
	maskIPs := true
	if opts.MaskIPs != nil {
		maskIPs = *opts.MaskIPs
	}

	res := ClusterResult{
		Grouping:   effectiveGrouping,
		Ranking:    RankingAnomalyFirst,
		TotalTasks: uint64(len(tasks)),
	}

	// Deterministic fallback when task count exceeds MaxTasks in normalized mode.
	if effectiveGrouping == GroupingNormalized && len(tasks) > MaxTasks {
		effectiveGrouping = GroupingExact
		res.Grouping = GroupingExact
		res.Truncated = true
	}

	if len(tasks) == 0 {
		return res
	}

	// Pass 1: O(N) classification with unconditional Tier 0 failure collection.
	var tier0Idx []int
	var pass2Idx []int
	for i := range tasks {
		t := &tasks[i]
		switch t.Status {
		case StatusOffline:
			res.OfflineHosts = append(res.OfflineHosts, t.Hostname)
			continue
		case StatusPending, StatusRunning, StatusUnspecified:
			res.UnfinishedHostsCount++
			continue
		}
		if isCleanSucceededTask(t) {
			pass2Idx = append(pass2Idx, i)
		} else {
			tier0Idx = append(tier0Idx, i)
		}
	}

	slices.Sort(res.OfflineHosts)

	// Sort indices deterministically by (Hostname ASC, HostID ASC) so quota
	// admission and representative selection are completely independent of input order.
	sortTaskIndices(tasks, tier0Idx)
	sortTaskIndices(tasks, pass2Idx)

	// Cluster Tier 0 failures (independent quota MaxFailureClusters).
	tier0Groups := clusterTier0(tasks, tier0Idx, effectiveGrouping, opts.Detailed, maskIPs)

	// Pass 2: cluster succeeded tasks.
	pass2Groups, pass2Overflowed := clusterPass2(tasks, pass2Idx, effectiveGrouping, opts.Detailed, maskIPs)
	if pass2Overflowed {
		res.Truncated = true
	}

	allGroups := make([]Group, 0, len(tier0Groups)+len(pass2Groups))
	allGroups = append(allGroups, tier0Groups...)
	allGroups = append(allGroups, pass2Groups...)

	SortGroups(allGroups)
	res.Groups = allGroups
	res.TotalGroups = uint64(len(allGroups))

	for _, g := range allGroups {
		if g.Severity == SeverityNormal && g.HostCount > uint64(len(g.Hosts)) {
			res.FoldedNormalHosts += g.HostCount - uint64(len(g.Hosts))
		}
	}

	return res
}

func isCleanSucceededTask(t *TaskInput) bool {
	return t.Status == StatusSucceeded &&
		t.ExitCode != nil &&
		*t.ExitCode == 0 &&
		t.Reason == "" &&
		len(t.StdoutHash) == 32 &&
		len(t.StderrHash) == 32
}

func sortTaskIndices(tasks []TaskInput, idxs []int) {
	slices.SortFunc(idxs, func(a, b int) int {
		if c := strings.Compare(tasks[a].Hostname, tasks[b].Hostname); c != 0 {
			return c
		}
		return strings.Compare(tasks[a].HostID, tasks[b].HostID)
	})
}

func classifyFailureTask(t *TaskInput) (sub uint8, anomalyReason string) {
	switch t.Status {
	case StatusTimeout:
		return 0, ReasonTimeout
	case StatusUnsupported:
		return 2, ReasonTaskUnsupported
	case StatusCancelled:
		return 3, ReasonTaskCancelled
	case StatusSkipped:
		return 4, ReasonTaskSkipped
	case StatusFailed:
		if t.ExitCode != nil && *t.ExitCode != 0 {
			return 1, ReasonNonZeroExit
		}
		return 1, ReasonTaskFailed
	}
	if t.ExitCode == nil {
		return 1, ReasonTaskFailed
	}
	if *t.ExitCode != 0 {
		return 1, ReasonNonZeroExit
	}
	return 5, ReasonErrorReason
}

func exitCodeKey(ec *int32) string {
	if ec == nil {
		return "nil"
	}
	return strconv.FormatInt(int64(*ec), 10)
}

func cloneExitCode(ec *int32) *int32 {
	if ec == nil {
		return nil
	}
	v := *ec
	return &v
}

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func combineTemplateHash(normOut, normErr string) [32]byte {
	h := sha256.New()
	h.Write([]byte(normOut))
	h.Write([]byte{0})
	h.Write([]byte(normErr))
	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}

func boundedPreviewPair(stdout, stderr []byte) (string, string) {
	outStr := textPrefix(stdout, MaxPreviewBytesPerStream)
	rem := MaxPreviewBytesPerStream - len(outStr)
	if rem < 0 {
		rem = 0
	}
	errStr := textPrefix(stderr, rem)
	return outStr, errStr
}

func textPrefix(b []byte, limit int) string {
	if len(b) == 0 || limit <= 0 {
		return ""
	}
	if len(b) > limit {
		b = b[:limit]
	}
	s := toValidUTF8(b)
	return truncateUTF8Bytes(s, limit)
}

func isTaskTruncated(t *TaskInput, shownOut, shownErr string) bool {
	return t.ResultTruncated ||
		uint64(len(shownOut)) < t.StdoutSize ||
		uint64(len(shownErr)) < t.StderrSize
}

type tier0Accum struct {
	group    Group
	allHosts []string
	metrics  *clusterMetrics
	hostData map[string]*TaskInput
}

func clusterTier0(tasks []TaskInput, idxs []int, grouping GroupingMode, detailed bool, maskIPs bool) []Group {
	if len(idxs) == 0 {
		return nil
	}

	byKey := make(map[string]*tier0Accum, min(len(idxs), MaxFailureClusters))
	var order []string
	normClusters := 0

	// Detect unified modes for Tier 0 tasks that have output hashes when normalized.
	var t0OutMode, t0ErrMode PreviewMode
	if grouping == GroupingNormalized {
		outSamples := make([]PreviewSample, 0, len(idxs))
		errSamples := make([]PreviewSample, 0, len(idxs))
		for _, idx := range idxs {
			t := &tasks[idx]
			if len(t.StdoutHash) == 32 && len(t.StderrHash) == 32 {
				outSamples = append(outSamples, PreviewSample{Data: t.Stdout, TotalSize: t.StdoutSize})
				errSamples = append(errSamples, PreviewSample{Data: t.Stderr, TotalSize: t.StderrSize})
			}
		}
		t0OutMode = DetectStreamMode(outSamples)
		t0ErrMode = DetectStreamMode(errSamples)
	}

	for _, idx := range idxs {
		t := &tasks[idx]
		sub, anomReason := classifyFailureTask(t)
		hasHashes := len(t.StdoutHash) == 32 && len(t.StderrHash) == 32
		ecKey := exitCodeKey(t.ExitCode)

		if !hasHashes {
			key := "nohash:" + strconv.Itoa(int(sub)) + ":" + strconv.Itoa(int(t.Status)) + ":" + ecKey + ":" + t.Reason
			acc := byKey[key]
			if acc == nil {
				acc = &tier0Accum{
					group: Group{
						Severity:      SeverityFailure,
						SeveritySub:   sub,
						AnomalyReason: anomReason,
						Status:        t.Status,
						ExitCode:      cloneExitCode(t.ExitCode),
						Reason:        t.Reason,
						Truncated:     t.ResultTruncated,
					},
				}
				byKey[key] = acc
				order = append(order, key)
			}
			acc.group.HostCount++
			acc.allHosts = append(acc.allHosts, t.Hostname)
			if t.ResultTruncated {
				acc.group.Truncated = true
			}
			if sub < acc.group.SeveritySub {
				acc.group.SeveritySub = sub
				acc.group.AnomalyReason = anomReason
				acc.group.Status = t.Status
			}
			continue
		}

		if grouping == GroupingExact {
			key := "exact:" + strconv.Itoa(int(sub)) + ":" + ecKey + ":" + t.Reason + ":" +
				hex.EncodeToString(t.StdoutHash) + ":" + hex.EncodeToString(t.StderrHash)
			acc := byKey[key]
			if acc == nil {
				outStr, errStr := boundedPreviewPair(t.Stdout, t.Stderr)
				acc = &tier0Accum{
					group: Group{
						Severity:      SeverityFailure,
						SeveritySub:   sub,
						AnomalyReason: anomReason,
						Status:        t.Status,
						ExitCode:      cloneExitCode(t.ExitCode),
						Reason:        t.Reason,
						StdoutHash:    cloneBytes(t.StdoutHash),
						StderrHash:    cloneBytes(t.StderrHash),
						Stdout:        outStr,
						Stderr:        errStr,
						Truncated:     isTaskTruncated(t, outStr, errStr),
					},
				}
				byKey[key] = acc
				order = append(order, key)
			}
			acc.group.HostCount++
			acc.allHosts = append(acc.allHosts, t.Hostname)
			if sub < acc.group.SeveritySub {
				acc.group.SeveritySub = sub
				acc.group.AnomalyReason = anomReason
				acc.group.Status = t.Status
			}
			continue
		}

		// Normalized Tier 0 clustering (independent quota MaxFailureClusters).
		outOpts := NormalizeOptions{
			Hostname:  t.Hostname,
			MaskIPs:   maskIPs,
			Mode:      t0OutMode,
			Truncated: t.StdoutSize > uint64(len(t.Stdout)) || len(t.Stdout) > MaxPreviewBytesPerStream,
		}
		errOpts := NormalizeOptions{
			Hostname:     t.Hostname,
			MaskIPs:      maskIPs,
			Mode:         t0ErrMode,
			Truncated:    t.StderrSize > uint64(len(t.Stderr)) || len(t.Stderr) > MaxPreviewBytesPerStream,
			StreamPrefix: "stderr.",
		}
		normOut := NormalizePreview(t.Stdout, outOpts)
		normErr := NormalizePreview(t.Stderr, errOpts)
		tmplHash := combineTemplateHash(normOut.Template, normErr.Template)

		key := "norm:" + strconv.Itoa(int(sub)) + ":" + ecKey + ":" + t.Reason + ":" + hex.EncodeToString(tmplHash[:])
		acc := byKey[key]
		if acc == nil {
			if normClusters >= MaxFailureClusters {
				// Aggregate overflow Tier 0 tasks by (statusSub, exitCode, reason) so zero failure hosts are lost.
				overflowKey := "t0overflow:" + strconv.Itoa(int(sub)) + ":" + ecKey + ":" + t.Reason
				acc = byKey[overflowKey]
				if acc == nil {
					outStr, errStr := boundedPreviewPair(t.Stdout, t.Stderr)
					acc = &tier0Accum{
						group: Group{
							Severity:      SeverityFailure,
							SeveritySub:   sub,
							AnomalyReason: anomReason,
							Status:        t.Status,
							ExitCode:      cloneExitCode(t.ExitCode),
							Reason:        t.Reason,
							Stdout:        outStr,
							Stderr:        errStr,
							Truncated:     true,
						},
					}
					byKey[overflowKey] = acc
					order = append(order, overflowKey)
				}
				acc.group.HostCount++
				acc.allHosts = append(acc.allHosts, t.Hostname)
				continue
			}
			normClusters++
			outStr, errStr := boundedPreviewPair(t.Stdout, t.Stderr)
			tmplOut := normOut.Template
			if tmplOut == outStr {
				tmplOut = ""
			}
			tmplErr := normErr.Template
			if tmplErr == errStr {
				tmplErr = ""
			}
			acc = &tier0Accum{
				group: Group{
					Severity:       SeverityFailure,
					SeveritySub:    sub,
					AnomalyReason:  anomReason,
					Status:         t.Status,
					ExitCode:       cloneExitCode(t.ExitCode),
					Reason:         t.Reason,
					TemplateHash:   cloneBytes(tmplHash[:]),
					Stdout:         outStr,
					Stderr:         errStr,
					TemplateStdout: tmplOut,
					TemplateStderr: tmplErr,
					Truncated:      isTaskTruncated(t, outStr, errStr) || normOut.Truncated || normErr.Truncated,
				},
				metrics:  newClusterMetrics(),
				hostData: make(map[string]*TaskInput, 4),
			}
			byKey[key] = acc
			order = append(order, key)
		}
		acc.group.HostCount++
		acc.allHosts = append(acc.allHosts, t.Hostname)
		if acc.metrics != nil {
			acc.metrics.addHostSlots(t.Hostname, normOut.Slots)
			acc.metrics.addHostSlots(t.Hostname, normErr.Slots)
		}
		if acc.hostData != nil {
			if _, exists := acc.hostData[t.Hostname]; !exists {
				acc.hostData[t.Hostname] = t
			}
		}
	}

	groups := make([]Group, 0, len(order))
	for _, key := range order {
		acc := byKey[key]
		if acc.metrics != nil {
			variances, typicalHost, extremeHost := acc.metrics.summarize()
			acc.group.Variances = variances
			acc.group.Hosts = selectGroupHosts(acc.allHosts, detailed, typicalHost, extremeHost)
			if typicalHost != "" && acc.hostData != nil {
				if rep := acc.hostData[typicalHost]; rep != nil {
					applyRepresentativeSample(&acc.group, rep)
				}
			}
		} else {
			acc.group.Hosts = selectGroupHosts(acc.allHosts, detailed, "", "")
		}
		capGroupPreviewBudget(&acc.group)
		groups = append(groups, acc.group)
	}
	return groups
}

type pass2Accum struct {
	group       Group
	allHosts    []string
	taskIdxs    []int
	hasStderr   bool
	metrics     *clusterMetrics
	rawNormOut  string
	rawNormErr  string
	hasOutliers bool
}

func clusterPass2(tasks []TaskInput, idxs []int, grouping GroupingMode, detailed bool, maskIPs bool) ([]Group, bool) {
	if len(idxs) == 0 {
		return nil, false
	}

	if grouping == GroupingExact {
		byKey := make(map[string]*pass2Accum, min(len(idxs), MaxClusters))
		var order []string
		for _, idx := range idxs {
			t := &tasks[idx]
			taskHasStderr := t.StderrSize > 0 || len(t.Stderr) > 0
			key := string(t.StdoutHash) + string(t.StderrHash)
			acc := byKey[key]
			if acc == nil {
				outStr, errStr := boundedPreviewPair(t.Stdout, t.Stderr)
				acc = &pass2Accum{
					group: Group{
						Status:     StatusSucceeded,
						ExitCode:   cloneExitCode(t.ExitCode),
						StdoutHash: cloneBytes(t.StdoutHash),
						StderrHash: cloneBytes(t.StderrHash),
						Stdout:     outStr,
						Stderr:     errStr,
						Truncated:  isTaskTruncated(t, outStr, errStr),
					},
				}
				byKey[key] = acc
				order = append(order, key)
			}
			acc.group.HostCount++
			acc.allHosts = append(acc.allHosts, t.Hostname)
			if taskHasStderr {
				acc.hasStderr = true
			}
		}
		var maxSucceededHosts uint64
		for _, key := range order {
			if hc := byKey[key].group.HostCount; hc > maxSucceededHosts {
				maxSucceededHosts = hc
			}
		}
		totalSucceededClusters := len(order)
		groups := make([]Group, 0, len(order))
		for _, key := range order {
			acc := byKey[key]
			acc.group.Hosts = selectGroupHosts(acc.allHosts, detailed, "", "")
			switch {
			case acc.hasStderr:
				acc.group.Severity = SeverityAnomaly
				acc.group.SeveritySub = 0
				acc.group.AnomalyReason = ReasonStderrPresent
			case totalSucceededClusters >= 2 && acc.group.HostCount < maxSucceededHosts:
				acc.group.Severity = SeverityAnomaly
				acc.group.SeveritySub = 1
				acc.group.AnomalyReason = ReasonMinorityCluster
			default:
				acc.group.Severity = SeverityNormal
				acc.group.SeveritySub = 0
				acc.group.AnomalyReason = ReasonMajorityNormal
			}
			groups = append(groups, acc.group)
		}
		return groups, false
	}

	byHash := make(map[[32]byte]*pass2Accum, min(len(idxs), MaxClusters))
	var order [][32]byte
	var overflow *pass2Accum

	outSamples := make([]PreviewSample, len(idxs))
	errSamples := make([]PreviewSample, len(idxs))
	for i, idx := range idxs {
		t := &tasks[idx]
		outSamples[i] = PreviewSample{Data: t.Stdout, TotalSize: t.StdoutSize}
		errSamples[i] = PreviewSample{Data: t.Stderr, TotalSize: t.StderrSize}
	}
	outMode := DetectStreamMode(outSamples)
	errMode := DetectStreamMode(errSamples)

	hasher := sha256.New()
	var zeroSep = [1]byte{0}

	for _, idx := range idxs {
		t := &tasks[idx]
		taskHasStderr := t.StderrSize > 0 || len(t.Stderr) > 0

		outOpts := NormalizeOptions{
			Hostname:  t.Hostname,
			MaskIPs:   maskIPs,
			Mode:      outMode,
			Truncated: t.StdoutSize > uint64(len(t.Stdout)) || len(t.Stdout) > MaxPreviewBytesPerStream,
		}
		normOut := NormalizePreview(t.Stdout, outOpts)
		var normErr NormalizeResult
		if len(t.Stderr) > 0 {
			errOpts := NormalizeOptions{
				Hostname:     t.Hostname,
				MaskIPs:      maskIPs,
				Mode:         errMode,
				Truncated:    t.StderrSize > uint64(len(t.Stderr)) || len(t.Stderr) > MaxPreviewBytesPerStream,
				StreamPrefix: "stderr.",
			}
			normErr = NormalizePreview(t.Stderr, errOpts)
		}

		hasher.Reset()
		hasher.Write([]byte(normOut.Template))
		hasher.Write(zeroSep[:])
		hasher.Write([]byte(normErr.Template))
		var tmplHash [32]byte
		hasher.Sum(tmplHash[:0])

		acc := byHash[tmplHash]
		if acc == nil {
			if len(order) >= MaxClusters {
				if overflow == nil {
					outStr, errStr := boundedPreviewPair(t.Stdout, t.Stderr)
					overflow = &pass2Accum{
						group: Group{
							Severity:      SeverityNormal,
							SeveritySub:   1,
							AnomalyReason: ReasonClusterLimitOverflow,
							Status:        StatusSucceeded,
							ExitCode:      cloneExitCode(t.ExitCode),
							Stdout:        outStr,
							Stderr:        errStr,
							Truncated:     true,
						},
					}
				}
				overflow.group.HostCount++
				overflow.allHosts = append(overflow.allHosts, t.Hostname)
				continue
			}
			outStr, errStr := boundedPreviewPair(t.Stdout, t.Stderr)
			acc = &pass2Accum{
				group: Group{
					Status:       StatusSucceeded,
					ExitCode:     cloneExitCode(t.ExitCode),
					TemplateHash: cloneBytes(tmplHash[:]),
					Stdout:       outStr,
					Stderr:       errStr,
					Truncated:    isTaskTruncated(t, outStr, errStr) || normOut.Truncated || normErr.Truncated,
				},
				metrics:    newClusterMetrics(),
				rawNormOut: normOut.Template,
				rawNormErr: normErr.Template,
			}
			byHash[tmplHash] = acc
			order = append(order, tmplHash)
		}
		acc.group.HostCount++
		acc.allHosts = append(acc.allHosts, t.Hostname)
		acc.taskIdxs = append(acc.taskIdxs, idx)
		if taskHasStderr {
			acc.hasStderr = true
		}
		if normOut.Truncated || normErr.Truncated || t.ResultTruncated {
			acc.group.Truncated = true
		}
		acc.metrics.addHostSlots(t.Hostname, normOut.Slots)
		acc.metrics.addHostSlots(t.Hostname, normErr.Slots)
	}

	var maxSucceededHosts uint64
	for _, key := range order {
		if hc := byHash[key].group.HostCount; hc > maxSucceededHosts {
			maxSucceededHosts = hc
		}
	}

	totalSucceededClusters := len(order)
	groups := make([]Group, 0, len(order)+1)
	for _, key := range order {
		acc := byHash[key]
		var typicalHost, extremeHost string
		if acc.metrics != nil {
			acc.group.Variances, typicalHost, extremeHost = acc.metrics.summarize()
			if len(acc.group.Variances) > 0 && len(acc.group.Variances[0].OutlierHosts) > 0 {
				acc.hasOutliers = true
			}
		}

		acc.group.Hosts = selectGroupHosts(acc.allHosts, detailed, typicalHost, extremeHost)
		if typicalHost != "" {
			for _, ti := range acc.taskIdxs {
				if tasks[ti].Hostname == typicalHost {
					applyRepresentativeSample(&acc.group, &tasks[ti])
					break
				}
			}
		}
		if acc.rawNormOut != acc.group.Stdout {
			acc.group.TemplateStdout = acc.rawNormOut
		}
		if acc.rawNormErr != acc.group.Stderr {
			acc.group.TemplateStderr = acc.rawNormErr
		}
		capGroupPreviewBudget(&acc.group)

		switch {
		case acc.hasStderr:
			acc.group.Severity = SeverityAnomaly
			acc.group.SeveritySub = 0
			acc.group.AnomalyReason = ReasonStderrPresent
		case totalSucceededClusters >= 2 && acc.group.HostCount < maxSucceededHosts:
			acc.group.Severity = SeverityAnomaly
			acc.group.SeveritySub = 1
			acc.group.AnomalyReason = ReasonMinorityCluster
		case acc.hasOutliers:
			acc.group.Severity = SeverityAnomaly
			acc.group.SeveritySub = 2
			acc.group.AnomalyReason = ReasonMetricOutlier
		default:
			acc.group.Severity = SeverityNormal
			acc.group.SeveritySub = 0
			acc.group.AnomalyReason = ReasonMajorityNormal
		}

		groups = append(groups, acc.group)
	}

	if overflow != nil {
		overflow.group.Hosts = selectGroupHosts(overflow.allHosts, detailed, "", "")
		groups = append(groups, overflow.group)
	}

	return groups, overflow != nil
}

func applyRepresentativeSample(g *Group, rep *TaskInput) {
	outStr, errStr := boundedPreviewPair(rep.Stdout, rep.Stderr)
	g.Stdout = outStr
	g.Stderr = errStr
	if isTaskTruncated(rep, outStr, errStr) {
		g.Truncated = true
	}
}

// capGroupPreviewBudget enforces the shared MaxPreviewBytesPerStream (4 KiB)
// ceiling across Stdout, Stderr, TemplateStdout, and TemplateStderr (design 5.3 / M1).
// When the combined size exceeds the ceiling, raw sample and normalized template
// split the budget fairly (up to half each, reusing slack from the shorter side).
func capGroupPreviewBudget(g *Group) {
	rawLen := len(g.Stdout) + len(g.Stderr)
	tmplLen := len(g.TemplateStdout) + len(g.TemplateStderr)
	if rawLen+tmplLen <= MaxPreviewBytesPerStream {
		return
	}
	half := MaxPreviewBytesPerStream / 2
	rawBudget := min(rawLen, half)
	tmplBudget := min(tmplLen, half)
	if rem := MaxPreviewBytesPerStream - rawBudget - tmplBudget; rem > 0 {
		if rawLen > rawBudget {
			add := min(rem, rawLen-rawBudget)
			rawBudget += add
			rem -= add
		}
		if rem > 0 && tmplLen > tmplBudget {
			tmplBudget += min(rem, tmplLen-tmplBudget)
		}
	}
	if rawLen > rawBudget {
		g.Stdout = truncateUTF8Bytes(g.Stdout, rawBudget)
		g.Stderr = truncateUTF8Bytes(g.Stderr, max(0, rawBudget-len(g.Stdout)))
		g.Truncated = true
	}
	if tmplLen > tmplBudget {
		g.TemplateStdout = truncateUTF8Bytes(g.TemplateStdout, tmplBudget)
		g.TemplateStderr = truncateUTF8Bytes(g.TemplateStderr, max(0, tmplBudget-len(g.TemplateStdout)))
		g.Truncated = true
	}
}

func selectGroupHosts(allHosts []string, detailed bool, typicalHost, extremeHost string) []string {
	if len(allHosts) == 0 {
		return nil
	}
	if detailed {
		out := make([]string, len(allHosts))
		copy(out, allHosts)
		return out
	}
	if extremeHost != "" {
		if typicalHost != "" && typicalHost != extremeHost {
			return []string{typicalHost, extremeHost}
		}
		// Fallback: pick first host != extremeHost + extremeHost.
		for _, h := range allHosts {
			if h != extremeHost {
				return []string{h, extremeHost}
			}
		}
		return []string{extremeHost}
	}
	limit := min(len(allHosts), ConciseSampleHosts)
	out := make([]string, limit)
	copy(out, allHosts[:limit])
	return out
}

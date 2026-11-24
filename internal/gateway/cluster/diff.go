package cluster

import (
	"encoding/hex"
	"math"
	"slices"
	"strconv"
	"strings"
)

// DiffOptions configures bounded cross-job diffing.
type DiffOptions struct {
	// Grouping selects GroupingNormalized (default when empty) or GroupingExact.
	Grouping GroupingMode
	// OnlyChanged omits unchanged pattern groups when true. When false, unchanged
	// pattern groups are appended after changed groups with Unchanged=true.
	OnlyChanged bool
	// ActionDefinitionChanged is propagated from the caller when base and target
	// jobs ran with different catalog action SHA-256 digests.
	ActionDefinitionChanged bool
	// MaskIPs controls IP masking in normalized mode. Nil defaults to true.
	MaskIPs *bool
}

// DefaultDiffOptions returns DiffOptions with normalized grouping and OnlyChanged=true.
func DefaultDiffOptions() DiffOptions {
	return DiffOptions{
		Grouping:    GroupingNormalized,
		OnlyChanged: true,
	}
}

// StatusTransition aggregates aligned hosts that changed execution status,
// exit code, or error reason between base and target jobs.
type StatusTransition struct {
	FromStatus   TaskStatus
	ToStatus     TaskStatus
	FromExitCode *int32
	ToExitCode   *int32
	Reason       string
	HostCount    uint64
	Hosts        []string
	Degradation  bool

	rankClass uint8 // 0=degradation, 1=anomaly-to-anomaly, 2=recovery
	toSubRank uint8
}

// PatternChange aggregates aligned hosts sharing the same (baseSig, targetSig, targetSeverity)
// transition. Only the top MaxDetailedPatternDiffs changed transitions receive bounded
// line-level diffs (at most MaxDiffLinesPerEntry removed/added lines, <= MaxDiffLineBytes each).
type PatternChange struct {
	BaseSeverity    Severity
	TargetSeverity  Severity
	HostCount       uint64
	Hosts           []string
	Unchanged       bool
	BasePreview     string
	TargetPreview   string
	RemovedLines    []string
	AddedLines      []string
	DiffComputed    bool
	BaseTruncated   bool
	TargetTruncated bool

	baseSig   string
	targetSig string
	baseRaw   string
	targetRaw string
}

// MetricDrift describes a significant structured numeric drift across aligned
// hosts in normalized diff mode. All float64 values are strictly finite;
// MaxDeltaPct is nil whenever the max-delta host's base value is zero.
type MetricDrift struct {
	Label       string
	Unit        string
	BaseP50     float64
	TargetP50   float64
	MaxDelta    float64
	MaxDeltaPct *float64
	MaxHost     string
	HostCount   uint64

	score float64
}

// DiffResult holds the complete bounded cross-job diff output.
type DiffResult struct {
	Grouping                GroupingMode
	ActionDefinitionChanged bool
	AddedHosts              []string
	RemovedHosts            []string
	ReplacedHosts           []string
	AddedHostsCount         uint64
	RemovedHostsCount       uint64
	ReplacedHostsCount      uint64
	UnchangedHostsCount     uint64
	StatusTransitions       []StatusTransition
	PatternChanges          []PatternChange
	TotalPatternChanges     uint64
	MetricDrifts            []MetricDrift
	Truncated               bool
}

type alignedPair struct {
	hostID string
	base   *TaskInput
	target *TaskInput
}

// Diff compares baseTasks and targetTasks by immutable HostID, producing
// host-set changes (including replaced hosts), degradation-first status
// transitions, anomaly-first aggregated pattern transitions with bounded
// line-level diffs for the top MaxDetailedPatternDiffs entries, and
// finite-float structured metric drifts.
func Diff(baseTasks, targetTasks []TaskInput, opts DiffOptions) DiffResult {
	effectiveGrouping := opts.Grouping
	if effectiveGrouping == "" {
		effectiveGrouping = GroupingNormalized
	}
	maskIPs := true
	if opts.MaskIPs != nil {
		maskIPs = *opts.MaskIPs
	}

	res := DiffResult{
		Grouping:                effectiveGrouping,
		ActionDefinitionChanged: opts.ActionDefinitionChanged,
	}

	if effectiveGrouping == GroupingNormalized && (len(baseTasks) > MaxTasks || len(targetTasks) > MaxTasks) {
		effectiveGrouping = GroupingExact
		res.Grouping = GroupingExact
		res.Truncated = true
	}

	// Step 1: Index by immutable HostID (fallback to Hostname only when HostID is empty).
	baseByID := make(map[string]*TaskInput, len(baseTasks))
	baseIDs := make([]string, 0, len(baseTasks))
	for i := range baseTasks {
		k := taskAlignmentKey(&baseTasks[i])
		if _, dup := baseByID[k]; !dup {
			baseIDs = append(baseIDs, k)
		}
		baseByID[k] = &baseTasks[i]
	}

	targetByID := make(map[string]*TaskInput, len(targetTasks))
	targetIDs := make([]string, 0, len(targetTasks))
	for i := range targetTasks {
		k := taskAlignmentKey(&targetTasks[i])
		if _, dup := targetByID[k]; !dup {
			targetIDs = append(targetIDs, k)
		}
		targetByID[k] = &targetTasks[i]
	}

	var common []alignedPair
	removedNames := make(map[string]struct{})
	addedNames := make(map[string]struct{})

	for _, id := range baseIDs {
		bt := baseByID[id]
		if tt, ok := targetByID[id]; ok {
			common = append(common, alignedPair{hostID: id, base: bt, target: tt})
		} else {
			res.RemovedHosts = append(res.RemovedHosts, bt.Hostname)
			removedNames[bt.Hostname] = struct{}{}
		}
	}
	for _, id := range targetIDs {
		tt := targetByID[id]
		if _, ok := baseByID[id]; !ok {
			res.AddedHosts = append(res.AddedHosts, tt.Hostname)
			addedNames[tt.Hostname] = struct{}{}
		}
	}

	slices.Sort(res.AddedHosts)
	slices.Sort(res.RemovedHosts)

	// Detect replaced hosts: same hostname appears in both removed and added (different HostID).
	for name := range removedNames {
		if _, both := addedNames[name]; both {
			res.ReplacedHosts = append(res.ReplacedHosts, name)
		}
	}
	slices.Sort(res.ReplacedHosts)

	res.AddedHostsCount = uint64(len(res.AddedHosts))
	res.RemovedHostsCount = uint64(len(res.RemovedHosts))
	res.ReplacedHostsCount = uint64(len(res.ReplacedHosts))

	if len(common) == 0 {
		return res
	}

	// Deterministic alignment order by (target.Hostname ASC, hostID ASC).
	slices.SortFunc(common, func(a, b alignedPair) int {
		if c := strings.Compare(a.target.Hostname, b.target.Hostname); c != 0 {
			return c
		}
		return strings.Compare(a.hostID, b.hostID)
	})

	// Step 2: Joint unified stream mode detection across base & target in normalized mode.
	var jointOutMode, jointErrMode PreviewMode
	if effectiveGrouping == GroupingNormalized {
		outSamples := make([]PreviewSample, 0, len(common)*2)
		errSamples := make([]PreviewSample, 0, len(common)*2)
		for _, p := range common {
			if len(p.base.StdoutHash) == 32 {
				outSamples = append(outSamples, PreviewSample{Data: p.base.Stdout, TotalSize: p.base.StdoutSize})
			}
			if len(p.target.StdoutHash) == 32 {
				outSamples = append(outSamples, PreviewSample{Data: p.target.Stdout, TotalSize: p.target.StdoutSize})
			}
			if len(p.base.StderrHash) == 32 {
				errSamples = append(errSamples, PreviewSample{Data: p.base.Stderr, TotalSize: p.base.StderrSize})
			}
			if len(p.target.StderrHash) == 32 {
				errSamples = append(errSamples, PreviewSample{Data: p.target.Stderr, TotalSize: p.target.StderrSize})
			}
		}
		jointOutMode = DetectStreamMode(outSamples)
		jointErrMode = DetectStreamMode(errSamples)
	}

	// Step 3: Compute status transitions, pattern transitions, and metric drift pairs.
	statusMap := make(map[string]*StatusTransition)
	var statusOrder []string

	changedPatternMap := make(map[string]*PatternChange)
	var changedPatternOrder []string

	unchangedPatternMap := make(map[string]*PatternChange)
	var unchangedPatternOrder []string

	type driftPair struct {
		host   string
		base   float64
		target float64
		delta  float64
	}
	type driftMetricBucket struct {
		label string
		unit  string
		pairs []driftPair
	}
	driftMap := make(map[string]*driftMetricBucket)
	var driftOrder []string

	var baseOutScratch, baseErrScratch, targetOutScratch, targetErrScratch normalizeScratch
	for _, p := range common {
		hostname := p.target.Hostname
		if hostname == "" {
			hostname = p.base.Hostname
		}

		// Status transition check.
		stChanged := p.base.Status != p.target.Status ||
			compareExitCodePtr(p.base.ExitCode, p.target.ExitCode) != 0 ||
			p.base.Reason != p.target.Reason
		if stChanged {
			trReason := p.target.Reason
			if trReason == "" {
				trReason = p.base.Reason
			}
			stKey := strconv.Itoa(int(p.base.Status)) + ":" + strconv.Itoa(int(p.target.Status)) + ":" +
				exitCodeKey(p.base.ExitCode) + ":" + exitCodeKey(p.target.ExitCode) + ":" + trReason
			tr := statusMap[stKey]
			if tr == nil {
				rankClass, toSub, deg := classifyStatusTransition(p.base, p.target)
				tr = &StatusTransition{
					FromStatus:   p.base.Status,
					ToStatus:     p.target.Status,
					FromExitCode: cloneExitCode(p.base.ExitCode),
					ToExitCode:   cloneExitCode(p.target.ExitCode),
					Reason:       trReason,
					Degradation:  deg,
					rankClass:    rankClass,
					toSubRank:    toSub,
				}
				statusMap[stKey] = tr
				statusOrder = append(statusOrder, stKey)
			}
			tr.HostCount++
			tr.Hosts = append(tr.Hosts, hostname)
		}

		// Pattern signature & normalization.
		baseInfo := buildDiffTaskInfo(p.base, effectiveGrouping, jointOutMode, jointErrMode, maskIPs, &baseOutScratch, &baseErrScratch)
		targetInfo := buildDiffTaskInfo(p.target, effectiveGrouping, jointOutMode, jointErrMode, maskIPs, &targetOutScratch, &targetErrScratch)

		// Collect metric drifts for hosts that succeeded in both base and target (normalized mode).
		if effectiveGrouping == GroupingNormalized && isCleanSucceededTask(p.base) && isCleanSucceededTask(p.target) {
			if len(baseInfo.slots) > 0 && len(targetInfo.slots) > 0 {
				baseSlotMap := make(map[string]MetricSlot, len(baseInfo.slots))
				for _, sl := range baseInfo.slots {
					baseSlotMap[sl.Label] = sl
				}
				for _, tsl := range targetInfo.slots {
					bsl, ok := baseSlotMap[tsl.Label]
					if !ok {
						continue
					}
					delta := tsl.Value - bsl.Value
					if !isFiniteFloat(bsl.Value) || !isFiniteFloat(tsl.Value) || !isFiniteFloat(delta) {
						continue
					}
					bkt := driftMap[tsl.Label]
					if bkt == nil {
						if len(driftOrder) >= MaxSlotsPerCluster*2 {
							continue
						}
						unit := tsl.Unit
						if unit == "" {
							unit = bsl.Unit
						}
						bkt = &driftMetricBucket{
							label: SanitizeLabel(tsl.Label),
							unit:  SanitizeLabel(unit),
						}
						driftMap[tsl.Label] = bkt
						driftOrder = append(driftOrder, tsl.Label)
					}
					if len(bkt.pairs) < MaxSamplesPerSlot {
						bkt.pairs = append(bkt.pairs, driftPair{
							host:   hostname,
							base:   bsl.Value,
							target: tsl.Value,
							delta:  delta,
						})
					}
				}
			}
		}

		patternChanged := stChanged || baseInfo.sig != targetInfo.sig
		patKey := baseInfo.sig + "\x00" + targetInfo.sig + "\x00" + strconv.Itoa(int(targetInfo.severity))
		if !patternChanged {
			res.UnchangedHostsCount++
			if !opts.OnlyChanged {
				pc := unchangedPatternMap[patKey]
				if pc == nil {
					pc = &PatternChange{
						BaseSeverity:    baseInfo.severity,
						TargetSeverity:  targetInfo.severity,
						Unchanged:       true,
						BasePreview:     baseInfo.preview,
						TargetPreview:   targetInfo.preview,
						BaseTruncated:   baseInfo.truncated,
						TargetTruncated: targetInfo.truncated,
						baseSig:         baseInfo.sig,
						targetSig:       targetInfo.sig,
					}
					unchangedPatternMap[patKey] = pc
					unchangedPatternOrder = append(unchangedPatternOrder, patKey)
				}
				pc.HostCount++
				pc.Hosts = append(pc.Hosts, hostname)
			}
			continue
		}

		pc := changedPatternMap[patKey]
		if pc == nil {
			pc = &PatternChange{
				BaseSeverity:    baseInfo.severity,
				TargetSeverity:  targetInfo.severity,
				Unchanged:       false,
				BasePreview:     baseInfo.preview,
				TargetPreview:   targetInfo.preview,
				BaseTruncated:   baseInfo.truncated,
				TargetTruncated: targetInfo.truncated,
				baseSig:         baseInfo.sig,
				targetSig:       targetInfo.sig,
				baseRaw:         baseInfo.diffText,
				targetRaw:       targetInfo.diffText,
			}
			changedPatternMap[patKey] = pc
			changedPatternOrder = append(changedPatternOrder, patKey)
		}
		pc.HostCount++
		pc.Hosts = append(pc.Hosts, hostname)
		if baseInfo.truncated {
			pc.BaseTruncated = true
		}
		if targetInfo.truncated {
			pc.TargetTruncated = true
		}
	}

	// Step 4: Sort StatusTransitions degradation-first.
	if len(statusOrder) > 0 {
		transitions := make([]StatusTransition, 0, len(statusOrder))
		for _, k := range statusOrder {
			transitions = append(transitions, *statusMap[k])
		}
		slices.SortFunc(transitions, compareStatusTransitions)
		res.StatusTransitions = transitions
	}

	// Step 5: Sort changed PatternChanges Anomaly-First and compute bounded line-level diff
	// only for the top MaxDetailedPatternDiffs (32) entries.
	changedList := make([]PatternChange, 0, len(changedPatternOrder))
	for _, k := range changedPatternOrder {
		changedList = append(changedList, *changedPatternMap[k])
	}
	slices.SortFunc(changedList, compareChangedPatterns)
	res.TotalPatternChanges = uint64(len(changedList))

	for i := range changedList {
		if i < MaxDetailedPatternDiffs {
			rem, add := computeBoundedLineDiff(changedList[i].baseRaw, changedList[i].targetRaw)
			changedList[i].RemovedLines = rem
			changedList[i].AddedLines = add
			changedList[i].DiffComputed = true
		}
		// Clear internal scratch strings.
		changedList[i].baseRaw = ""
		changedList[i].targetRaw = ""
	}

	if !opts.OnlyChanged && len(unchangedPatternOrder) > 0 {
		unchangedList := make([]PatternChange, 0, len(unchangedPatternOrder))
		for _, k := range unchangedPatternOrder {
			unchangedList = append(unchangedList, *unchangedPatternMap[k])
		}
		slices.SortFunc(unchangedList, func(a, b PatternChange) int {
			if a.HostCount != b.HostCount {
				if a.HostCount > b.HostCount {
					return -1
				}
				return 1
			}
			if c := strings.Compare(firstHost(a.Hosts), firstHost(b.Hosts)); c != 0 {
				return c
			}
			return strings.Compare(a.targetSig, b.targetSig)
		})
		changedList = append(changedList, unchangedList...)
	}
	res.PatternChanges = changedList

	// Step 6: Compute significant MetricDrifts (top MaxMetricDrifts = 10, finite float invariant).
	if len(driftOrder) > 0 {
		var drifts []MetricDrift
		for _, lbl := range driftOrder {
			bkt := driftMap[lbl]
			if len(bkt.pairs) == 0 {
				continue
			}
			bases := make([]float64, len(bkt.pairs))
			targets := make([]float64, len(bkt.pairs))
			var best *driftPair
			bestAbs := -1.0
			for i := range bkt.pairs {
				pr := &bkt.pairs[i]
				bases[i] = pr.base
				targets[i] = pr.target
				if !isSignificantDrift(bkt.unit, pr.base, pr.target, pr.delta) {
					continue
				}
				ad := math.Abs(pr.delta)
				if best == nil || ad > bestAbs || (ad == bestAbs && pr.host < best.host) {
					best = pr
					bestAbs = ad
				}
			}
			if best == nil {
				continue
			}
			slices.Sort(bases)
			slices.Sort(targets)
			baseP50 := medianFloat64(bases)
			targetP50 := medianFloat64(targets)
			if !isFiniteFloat(baseP50) || !isFiniteFloat(targetP50) || !isFiniteFloat(best.delta) {
				continue
			}

			var maxDeltaPct *float64
			var score float64
			if best.base != 0 {
				pct := (best.delta / math.Abs(best.base)) * 100.0
				if isFiniteFloat(pct) {
					pCopy := pct
					maxDeltaPct = &pCopy
				}
			}
			if bkt.unit == "%" {
				score = math.Abs(best.delta)
			} else if maxDeltaPct != nil {
				score = math.Abs(*maxDeltaPct)
			} else {
				score = 100.0 + math.Abs(best.delta)
			}
			if !isFiniteFloat(score) {
				score = 0
			}

			drifts = append(drifts, MetricDrift{
				Label:       bkt.label,
				Unit:        bkt.unit,
				BaseP50:     baseP50,
				TargetP50:   targetP50,
				MaxDelta:    best.delta,
				MaxDeltaPct: maxDeltaPct,
				MaxHost:     best.host,
				HostCount:   uint64(len(bkt.pairs)),
				score:       score,
			})
		}

		slices.SortFunc(drifts, func(a, b MetricDrift) int {
			if a.score != b.score {
				if a.score > b.score {
					return -1
				}
				return 1
			}
			aa := math.Abs(a.MaxDelta)
			ba := math.Abs(b.MaxDelta)
			if aa != ba {
				if aa > ba {
					return -1
				}
				return 1
			}
			return strings.Compare(a.Label, b.Label)
		})
		if len(drifts) > MaxMetricDrifts {
			drifts = drifts[:MaxMetricDrifts]
		}
		res.MetricDrifts = drifts
	}

	return res
}

func taskAlignmentKey(t *TaskInput) string {
	if t.HostID != "" {
		return "id:" + t.HostID
	}
	return "name:" + t.Hostname
}

func isHealthySucceeded(t *TaskInput) bool {
	return t.Status == StatusSucceeded && t.ExitCode != nil && *t.ExitCode == 0 && t.Reason == ""
}

func classifyStatusTransition(base, target *TaskInput) (rankClass uint8, toSub uint8, degradation bool) {
	baseHealthy := isHealthySucceeded(base)
	targetHealthy := isHealthySucceeded(target)
	switch {
	case baseHealthy && !targetHealthy:
		degradation = true
		rankClass = 0
	case !baseHealthy && !targetHealthy:
		rankClass = 1
	default: // !baseHealthy && targetHealthy (recovery)
		rankClass = 2
	}
	if target.Status == StatusOffline {
		toSub = 2 // after timeout(0) and failed/nonzero(1)
	} else if !targetHealthy {
		sub, _ := classifyFailureTask(target)
		if sub >= 2 {
			sub++ // keep offline at 2
		}
		toSub = sub
	}
	return rankClass, toSub, degradation
}

func compareStatusTransitions(a, b StatusTransition) int {
	if a.rankClass != b.rankClass {
		if a.rankClass < b.rankClass {
			return -1
		}
		return 1
	}
	if a.toSubRank != b.toSubRank {
		if a.toSubRank < b.toSubRank {
			return -1
		}
		return 1
	}
	if a.HostCount != b.HostCount {
		if a.HostCount > b.HostCount {
			return -1
		}
		return 1
	}
	if a.FromStatus != b.FromStatus {
		if a.FromStatus < b.FromStatus {
			return -1
		}
		return 1
	}
	if a.ToStatus != b.ToStatus {
		if a.ToStatus < b.ToStatus {
			return -1
		}
		return 1
	}
	if c := strings.Compare(a.Reason, b.Reason); c != 0 {
		return c
	}
	return strings.Compare(firstHost(a.Hosts), firstHost(b.Hosts))
}

func compareChangedPatterns(a, b PatternChange) int {
	if a.TargetSeverity != b.TargetSeverity {
		if a.TargetSeverity < b.TargetSeverity {
			return -1
		}
		return 1
	}
	if a.TargetSeverity == SeverityFailure {
		if a.HostCount != b.HostCount {
			if a.HostCount > b.HostCount {
				return -1
			}
			return 1
		}
	} else {
		// Minority transitions before fleet-wide synchronous transitions (design 6.2).
		if a.HostCount != b.HostCount {
			if a.HostCount < b.HostCount {
				return -1
			}
			return 1
		}
	}
	if c := strings.Compare(firstHost(a.Hosts), firstHost(b.Hosts)); c != 0 {
		return c
	}
	if c := strings.Compare(a.targetSig, b.targetSig); c != 0 {
		return c
	}
	return strings.Compare(a.baseSig, b.baseSig)
}

type diffTaskInfo struct {
	sig       string
	severity  Severity
	preview   string
	diffText  string
	truncated bool
	slots     []MetricSlot
}

func singleTaskSeverity(t *TaskInput) Severity {
	if t.Status == StatusOffline || !isHealthySucceeded(t) || len(t.StdoutHash) != 32 || len(t.StderrHash) != 32 {
		return SeverityFailure
	}
	if t.StderrSize > 0 || len(t.Stderr) > 0 {
		return SeverityAnomaly
	}
	return SeverityNormal
}

func buildDiffTaskInfo(t *TaskInput, grouping GroupingMode, outMode, errMode PreviewMode, maskIPs bool, outScratch, errScratch *normalizeScratch) diffTaskInfo {
	sev := singleTaskSeverity(t)
	hasHashes := len(t.StdoutHash) == 32 && len(t.StderrHash) == 32
	metaPrefix := strconv.Itoa(int(t.Status)) + ":" + exitCodeKey(t.ExitCode) + ":" + t.Reason

	if !hasHashes {
		return diffTaskInfo{
			sig:       "nohash:" + metaPrefix,
			severity:  sev,
			truncated: t.ResultTruncated,
		}
	}

	outTrunc := t.StdoutSize > uint64(len(t.Stdout)) || len(t.Stdout) > MaxPreviewBytesPerStream
	errTrunc := t.StderrSize > uint64(len(t.Stderr)) || len(t.Stderr) > MaxPreviewBytesPerStream

	if grouping == GroupingExact {
		outStr, errStr := boundedPreviewPair(t.Stdout, t.Stderr)
		preview := combineStreamPreview(outStr, errStr)
		diffOut := preparePreviewText(capPreviewBytes(t.Stdout), outTrunc)
		diffErr := preparePreviewText(capPreviewBytes(t.Stderr), errTrunc)
		return diffTaskInfo{
			sig:       "exact:" + metaPrefix + ":" + hex.EncodeToString(t.StdoutHash) + ":" + hex.EncodeToString(t.StderrHash),
			severity:  sev,
			preview:   preview,
			diffText:  combineStreamPreview(diffOut, diffErr),
			truncated: isTaskTruncated(t, outStr, errStr),
		}
	}

	normOut := normalizePreviewWithScratch(t.Stdout, NormalizeOptions{
		Hostname:  t.Hostname,
		MaskIPs:   maskIPs,
		Mode:      outMode,
		Truncated: outTrunc,
	}, outScratch, false)
	var normErr NormalizeResult
	if len(t.Stderr) > 0 {
		normErr = normalizePreviewWithScratch(t.Stderr, NormalizeOptions{
			Hostname:     t.Hostname,
			MaskIPs:      maskIPs,
			Mode:         errMode,
			Truncated:    errTrunc,
			StreamPrefix: "stderr.",
		}, errScratch, false)
	}
	tmplHash := combineTemplateHash(normOut.Template, normErr.Template)
	combined := combineStreamPreview(normOut.Template, normErr.Template)

	var allSlots []MetricSlot
	if len(normErr.Slots) == 0 {
		allSlots = normOut.Slots
	} else if len(normOut.Slots) == 0 {
		allSlots = normErr.Slots
	} else {
		allSlots = make([]MetricSlot, 0, len(normOut.Slots)+len(normErr.Slots))
		allSlots = append(allSlots, normOut.Slots...)
		allSlots = append(allSlots, normErr.Slots...)
	}

	return diffTaskInfo{
		sig:       "norm:" + metaPrefix + ":" + hex.EncodeToString(tmplHash[:]),
		severity:  sev,
		preview:   truncateUTF8Bytes(combined, MaxPreviewBytesPerStream),
		diffText:  combined,
		truncated: t.ResultTruncated || outTrunc || errTrunc || normOut.Truncated || normErr.Truncated,
		slots:     allSlots,
	}
}

func combineStreamPreview(stdout, stderr string) string {
	if stderr == "" {
		return stdout
	}
	if stdout == "" {
		return "[stderr]\n" + stderr
	}
	return stdout + "\n[stderr]\n" + stderr
}

func isSignificantDrift(unit string, base, target, delta float64) bool {
	if unit == "%" {
		return math.Abs(delta) >= 10.0
	}
	if base != 0 {
		rel := math.Abs(delta / base)
		return isFiniteFloat(rel) && rel >= 0.20 && math.Abs(delta) >= 1.0
	}
	return math.Abs(target) >= 1.0
}

// computeBoundedLineDiff performs a deterministic bounded line-level diff:
//  1. Splits into at most MaxLinesPerPreview (128) lines.
//  2. Trims common prefix and common suffix lines.
//  3. Runs exact LCS on the bounded middle slices (<= 128 x 128).
//  4. Emits at most MaxDiffLinesPerEntry (6) removed lines and 6 added lines,
//     each truncated to valid UTF-8 <= MaxDiffLineBytes (256 bytes).
func computeBoundedLineDiff(baseText, targetText string) (removed []string, added []string) {
	if baseText == targetText {
		return nil, nil
	}
	a := splitBoundedDiffLines(baseText)
	b := splitBoundedDiffLines(targetText)

	// Trim common prefix.
	prefix := 0
	for prefix < len(a) && prefix < len(b) && a[prefix] == b[prefix] {
		prefix++
	}
	a = a[prefix:]
	b = b[prefix:]

	// Trim common suffix.
	suffix := 0
	for suffix < len(a) && suffix < len(b) && a[len(a)-1-suffix] == b[len(b)-1-suffix] {
		suffix++
	}
	a = a[:len(a)-suffix]
	b = b[:len(b)-suffix]

	if len(a) == 0 && len(b) == 0 {
		return nil, nil
	}
	if len(a) == 0 {
		return nil, capDiffLines(b)
	}
	if len(b) == 0 {
		return capDiffLines(a), nil
	}

	// Bounded LCS table: m, k <= MaxLinesPerPreview (128).
	m, k := len(a), len(b)
	cols := k + 1
	dp := make([]uint16, (m+1)*cols)
	for i := m - 1; i >= 0; i-- {
		row := i * cols
		nextRow := (i + 1) * cols
		for j := k - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[row+j] = dp[nextRow+j+1] + 1
			} else if dp[nextRow+j] >= dp[row+j+1] {
				dp[row+j] = dp[nextRow+j]
			} else {
				dp[row+j] = dp[row+j+1]
			}
		}
	}

	i, j := 0, 0
	for i < m && j < k {
		if a[i] == b[j] {
			i++
			j++
		} else if dp[(i+1)*cols+j] >= dp[i*cols+j+1] {
			if len(removed) < MaxDiffLinesPerEntry {
				removed = append(removed, truncateUTF8Bytes(a[i], MaxDiffLineBytes))
			}
			i++
		} else {
			if len(added) < MaxDiffLinesPerEntry {
				added = append(added, truncateUTF8Bytes(b[j], MaxDiffLineBytes))
			}
			j++
		}
		if len(removed) >= MaxDiffLinesPerEntry && len(added) >= MaxDiffLinesPerEntry {
			break
		}
	}
	for i < m && len(removed) < MaxDiffLinesPerEntry {
		removed = append(removed, truncateUTF8Bytes(a[i], MaxDiffLineBytes))
		i++
	}
	for j < k && len(added) < MaxDiffLinesPerEntry {
		added = append(added, truncateUTF8Bytes(b[j], MaxDiffLineBytes))
		j++
	}

	return removed, added
}

func splitBoundedDiffLines(s string) []string {
	if s == "" {
		return nil
	}
	var lines []string
	pos := 0
	for pos <= len(s) && len(lines) < MaxLinesPerPreview {
		nl := strings.IndexByte(s[pos:], '\n')
		var line string
		var hasNL bool
		if nl < 0 {
			line = s[pos:]
			pos = len(s) + 1
		} else {
			line = s[pos : pos+nl]
			pos += nl + 1
			hasNL = true
		}
		line = strings.TrimRight(line, "\r")
		lines = append(lines, line)
		if hasNL && pos == len(s) {
			break
		}
	}
	return lines
}

func capDiffLines(lines []string) []string {
	limit := min(len(lines), MaxDiffLinesPerEntry)
	out := make([]string, limit)
	for i := 0; i < limit; i++ {
		out[i] = truncateUTF8Bytes(lines[i], MaxDiffLineBytes)
	}
	return out
}

package job

import (
	"bytes"
	"context"
	"slices"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/cluster"
	"google.golang.org/protobuf/proto"
)

func (s *Service) DiffJobs(ctx context.Context, r *v1.DiffJobsRequest) (*v1.DiffJobsResponse, error) {
	m, err := s.operation(ctx, "diff_jobs", false, func(ctx context.Context) (proto.Message, error) {
		if r == nil {
			return nil, failure(connect.CodeInvalidArgument, "REQUEST_REQUIRED")
		}
		if r.BaseJobId == "" || r.TargetJobId == "" {
			return nil, failure(connect.CodeInvalidArgument, "JOB_ID_REQUIRED")
		}
		grouping, err := groupingMode(r.Grouping, cluster.GroupingNormalized)
		if err != nil {
			return nil, err
		}
		onlyChanged := true
		if r.OnlyChanged != nil {
			onlyChanged = *r.OnlyChanged
		}

		state := operationInfo(ctx)
		var baseJob, targetJob *v1.Job
		var latestVersion uint64
		var allRules []string
		recordAuth := func(v uint64, rules []string) {
			if v > latestVersion {
				latestVersion = v
			}
			allRules = append(allRules, rules...)
		}
		defer func() {
			if state == nil {
				return
			}
			if targetJob != nil {
				state.JobID = targetJob.JobId
			}
			if baseJob != nil {
				state.Resource = "job:" + baseJob.JobId
			}
			if latestVersion > 0 {
				state.Version = latestVersion
			}
			if len(allRules) > 0 {
				state.Rules = dedupeStrings(allRules)
			} else if len(state.Rules) > 0 {
				state.Rules = dedupeStrings(state.Rules)
			}
		}()

		baseJob, err = s.get(ctx, r.BaseJobId)
		if err != nil {
			return nil, err
		}
		targetJob, err = s.get(ctx, r.TargetJobId)
		if err != nil {
			return nil, err
		}

		// Authorize view_jobs on both jobs before checking action equality or status
		// so unauthorized callers cannot probe metadata of foreign jobs.
		v, rules, err := s.authorize(ctx, baseJob, authz.ViewJobs, false, "")
		recordAuth(v, rules)
		if err != nil {
			return nil, err
		}
		v, rules, err = s.authorize(ctx, targetJob, authz.ViewJobs, false, "")
		recordAuth(v, rules)
		if err != nil {
			return nil, err
		}

		if baseJob.Action != targetJob.Action {
			return nil, failure(connect.CodeInvalidArgument, "DIFF_ACTION_MISMATCH")
		}
		if isUnfinishedJobStatus(baseJob.Status) || isUnfinishedJobStatus(targetJob.Status) {
			return nil, failure(connect.CodeFailedPrecondition, "DIFF_JOB_NOT_FINISHED")
		}
		if baseJob.Status == v1.JobStatus_JOB_STATUS_DENIED || targetJob.Status == v1.JobStatus_JOB_STATUS_DENIED {
			return nil, failure(connect.CodeFailedPrecondition, "DIFF_JOB_DENIED")
		}

		// Authorize view_output on both jobs (host-level ABAC for every host in both jobs).
		v, rules, err = s.authorize(ctx, baseJob, authz.ViewOutput, false, "")
		recordAuth(v, rules)
		if err != nil {
			return nil, err
		}
		v, rules, err = s.authorize(ctx, targetJob, authz.ViewOutput, false, "")
		recordAuth(v, rules)
		if err != nil {
			return nil, err
		}

		release, err := s.acquireAnalysis(ctx)
		if err != nil {
			return nil, err
		}
		defer release()

		basePreviews, err := s.Previews.Load(ctx, baseJob.JobId)
		if err != nil {
			return nil, err
		}
		targetPreviews := basePreviews
		if targetJob.JobId != baseJob.JobId {
			targetPreviews, err = s.Previews.Load(ctx, targetJob.JobId)
			if err != nil {
				return nil, err
			}
		}

		diffRes := cluster.Diff(
			previewsToTaskInputs(basePreviews),
			previewsToTaskInputs(targetPreviews),
			cluster.DiffOptions{
				Grouping:                grouping,
				OnlyChanged:             onlyChanged,
				ActionDefinitionChanged: !bytes.Equal(baseJob.ActionSha256, targetJob.ActionSha256),
			},
		)

		resp := &v1.DiffJobsResponse{
			BaseJob:   baseJob,
			TargetJob: targetJob,
			Diff:      clusterDiffToProto(diffRes),
		}
		if err := trimDiffResponse(resp, ResponseBytes); err != nil {
			return nil, err
		}
		return resp, nil
	})
	if err != nil {
		return nil, err
	}
	return m.(*v1.DiffJobsResponse), nil
}

func isUnfinishedJobStatus(status v1.JobStatus) bool {
	return status == v1.JobStatus_JOB_STATUS_QUEUED ||
		status == v1.JobStatus_JOB_STATUS_RUNNING ||
		status == v1.JobStatus_JOB_STATUS_UNSPECIFIED
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func clusterDiffToProto(res cluster.DiffResult) *v1.JobDiff {
	transitions := make([]*v1.StatusTransition, 0, len(res.StatusTransitions))
	for _, st := range res.StatusTransitions {
		var fromEC, toEC *int32
		if st.FromExitCode != nil {
			v := *st.FromExitCode
			fromEC = &v
		}
		if st.ToExitCode != nil {
			v := *st.ToExitCode
			toEC = &v
		}
		transitions = append(transitions, &v1.StatusTransition{
			FromStatus:   clusterToProtoStatus(st.FromStatus),
			ToStatus:     clusterToProtoStatus(st.ToStatus),
			FromExitCode: fromEC,
			ToExitCode:   toEC,
			Reason:       st.Reason,
			HostCount:    st.HostCount,
			Hosts:        slices.Clone(st.Hosts),
			Degradation:  st.Degradation,
		})
	}

	patterns := make([]*v1.PatternChange, 0, len(res.PatternChanges))
	for _, pc := range res.PatternChanges {
		patterns = append(patterns, &v1.PatternChange{
			BaseSeverity:    clusterToProtoSeverity(pc.BaseSeverity),
			TargetSeverity:  clusterToProtoSeverity(pc.TargetSeverity),
			HostCount:       pc.HostCount,
			Hosts:           slices.Clone(pc.Hosts),
			Unchanged:       pc.Unchanged,
			BasePreview:     pc.BasePreview,
			TargetPreview:   pc.TargetPreview,
			RemovedLines:    slices.Clone(pc.RemovedLines),
			AddedLines:      slices.Clone(pc.AddedLines),
			DiffComputed:    pc.DiffComputed,
			BaseTruncated:   pc.BaseTruncated,
			TargetTruncated: pc.TargetTruncated,
		})
	}

	drifts := make([]*v1.MetricDrift, 0, len(res.MetricDrifts))
	for _, d := range res.MetricDrifts {
		var maxDeltaPct *float64
		if d.MaxDeltaPct != nil {
			v := *d.MaxDeltaPct
			maxDeltaPct = &v
		}
		drifts = append(drifts, &v1.MetricDrift{
			Label:          d.Label,
			Unit:           d.Unit,
			BaseP50:        d.BaseP50,
			TargetP50:      d.TargetP50,
			BaseMax:        d.BaseMax,
			TargetMax:      d.TargetMax,
			MaxDelta:       d.MaxDelta,
			MaxDeltaBase:   d.MaxDeltaBase,
			MaxDeltaTarget: d.MaxDeltaTarget,
			MaxDeltaPct:    maxDeltaPct,
			MaxHost:        d.MaxHost,
			AffectedHosts:  d.AffectedHosts,
			HostCount:      d.HostCount,
		})
	}

	return &v1.JobDiff{
		OutputTrust:             v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED,
		Truncated:               res.Truncated,
		PreviewTruncated:        res.PreviewTruncated,
		ActionDefinitionChanged: res.ActionDefinitionChanged,
		Grouping:                string(res.Grouping),
		UnchangedHostsCount:     res.UnchangedHostsCount,
		AddedHostsCount:         res.AddedHostsCount,
		AddedHosts:              slices.Clone(res.AddedHosts),
		RemovedHostsCount:       res.RemovedHostsCount,
		RemovedHosts:            slices.Clone(res.RemovedHosts),
		ReplacedHostsCount:      res.ReplacedHostsCount,
		ReplacedHosts:           slices.Clone(res.ReplacedHosts),
		StatusTransitions:       transitions,
		TotalPatternChanges:     res.TotalPatternChanges,
		OmittedPatternChanges:   0,
		PatternChanges:          patterns,
		MetricDrifts:            drifts,
	}
}

func shrinkStatusTransition(st *v1.StatusTransition) bool {
	switch {
	case len(st.Hosts) > 2:
		st.Hosts = st.Hosts[:2]
	case len(st.Hosts) > 0:
		st.Hosts = nil
	default:
		return false
	}
	return true
}

func shrinkPatternChange(pc *v1.PatternChange) bool {
	switch {
	case len(pc.Hosts) > 2:
		pc.Hosts = pc.Hosts[:2]
	case len(pc.AddedLines) > 0:
		pc.AddedLines = pc.AddedLines[:len(pc.AddedLines)-1]
	case len(pc.RemovedLines) > 0:
		pc.RemovedLines = pc.RemovedLines[:len(pc.RemovedLines)-1]
	case pc.TargetPreview != "":
		pc.TargetPreview = ""
		pc.TargetTruncated = true
	case pc.BasePreview != "":
		pc.BasePreview = ""
		pc.BaseTruncated = true
	case len(pc.Hosts) > 0:
		pc.Hosts = nil
	default:
		return false
	}
	return true
}

// trimDiffResponse enforces ResponseBytes (32 KiB) on the full DiffJobsResponse
// (both protojson and binary protobuf) in linear O(N) time.
//
// Highest-value items are admitted first:
//  1. StatusTransitions (degradation-first)
//  2. PatternChanges (anomaly-first)
//  3. MetricDrifts (most significant first)
//  4. Hostname lists: ReplacedHosts, RemovedHosts, AddedHosts (preserving *_count)
//
// Lower-priority fields are trimmed first if the final exact verification exceeds limit.
func trimDiffResponse(resp *v1.DiffJobsResponse, limit int) error {
	diff := resp.Diff
	if diff == nil {
		return nil
	}

	if len(diff.StatusTransitions) <= 8 &&
		len(diff.PatternChanges) <= 8 &&
		len(diff.MetricDrifts) <= 10 &&
		len(diff.AddedHosts)+len(diff.RemovedHosts)+len(diff.ReplacedHosts) <= 64 {
		sz, err := encodedMessageSize(resp)
		if err != nil {
			return err
		}
		if sz <= limit {
			return nil
		}
	}

	allTransitions := diff.StatusTransitions
	allPatterns := diff.PatternChanges
	allDrifts := diff.MetricDrifts
	allReplaced := diff.ReplacedHosts
	allRemoved := diff.RemovedHosts
	allAdded := diff.AddedHosts

	baseDiff := &v1.JobDiff{
		OutputTrust:             diff.OutputTrust,
		Truncated:               true,
		PreviewTruncated:        diff.PreviewTruncated,
		ActionDefinitionChanged: diff.ActionDefinitionChanged,
		Grouping:                diff.Grouping,
		UnchangedHostsCount:     diff.UnchangedHostsCount,
		AddedHostsCount:         diff.AddedHostsCount,
		RemovedHostsCount:       diff.RemovedHostsCount,
		ReplacedHostsCount:      diff.ReplacedHostsCount,
		TotalPatternChanges:     diff.TotalPatternChanges,
		OmittedPatternChanges:   diff.TotalPatternChanges,
	}
	baseSize, err := encodedMessageSize(&v1.DiffJobsResponse{
		BaseJob:   resp.BaseJob,
		TargetJob: resp.TargetJob,
		Diff:      baseDiff,
	})
	if err != nil {
		return err
	}

	// Reserve structural overhead for repeated JSON array keys and brackets.
	used := baseSize + 192
	truncated := diff.Truncated
	budgetFull := false

	// 1. StatusTransitions (highest priority).
	keptTransitions := make([]*v1.StatusTransition, 0, min(len(allTransitions), 16))
	for _, st := range allTransitions {
		sz, err := encodedMessageSize(st)
		if err != nil {
			return err
		}
		if used+sz+4 <= limit {
			keptTransitions = append(keptTransitions, st)
			used += sz + 4
			continue
		}
		truncated = true
		budgetFull = true
		fitted := false
		for shrinkStatusTransition(st) {
			sz, err = encodedMessageSize(st)
			if err != nil {
				return err
			}
			if used+sz+4 <= limit {
				fitted = true
				break
			}
		}
		if fitted {
			keptTransitions = append(keptTransitions, st)
			used += sz + 4
		}
		break
	}

	// 2. PatternChanges (second priority).
	keptPatterns := make([]*v1.PatternChange, 0, min(len(allPatterns), 16))
	patOmitStart := 0
	if !budgetFull {
		patOmitStart = len(allPatterns)
		for i, pc := range allPatterns {
			sz, err := encodedMessageSize(pc)
			if err != nil {
				return err
			}
			if used+sz+4 <= limit {
				keptPatterns = append(keptPatterns, pc)
				used += sz + 4
				continue
			}
			truncated = true
			budgetFull = true
			fitted := false
			for shrinkPatternChange(pc) {
				sz, err = encodedMessageSize(pc)
				if err != nil {
					return err
				}
				if used+sz+4 <= limit {
					fitted = true
					break
				}
			}
			if fitted {
				keptPatterns = append(keptPatterns, pc)
				used += sz + 4
				patOmitStart = i + 1
			} else {
				patOmitStart = i
			}
			break
		}
	}

	var omittedPatterns uint64
	for k := patOmitStart; k < len(allPatterns); k++ {
		if !allPatterns[k].Unchanged {
			omittedPatterns++
		}
	}
	if patOmitStart < len(allPatterns) {
		truncated = true
	}

	// 3. MetricDrifts (third priority).
	keptDrifts := make([]*v1.MetricDrift, 0, len(allDrifts))
	if !budgetFull {
		for _, d := range allDrifts {
			sz, err := encodedMessageSize(d)
			if err != nil {
				return err
			}
			if used+sz+4 <= limit {
				keptDrifts = append(keptDrifts, d)
				used += sz + 4
				continue
			}
			truncated = true
			budgetFull = true
			break
		}
	} else if len(allDrifts) > 0 {
		truncated = true
	}

	// 4. Hostname lists (lowest priority; counts are always preserved).
	trimHostList := func(hosts []string) []string {
		if len(hosts) == 0 {
			return nil
		}
		if budgetFull {
			truncated = true
			return nil
		}
		kept := make([]string, 0, min(len(hosts), 32))
		for _, h := range hosts {
			hSize := jsonStringEncodedSize(h) + 3
			if used+hSize > limit {
				truncated = true
				budgetFull = true
				break
			}
			kept = append(kept, h)
			used += hSize
		}
		return kept
	}
	keptReplaced := trimHostList(allReplaced)
	keptRemoved := trimHostList(allRemoved)
	keptAdded := trimHostList(allAdded)

	diff.StatusTransitions = keptTransitions
	diff.PatternChanges = keptPatterns
	diff.OmittedPatternChanges = omittedPatterns
	diff.MetricDrifts = keptDrifts
	diff.ReplacedHosts = keptReplaced
	diff.RemovedHosts = keptRemoved
	diff.AddedHosts = keptAdded
	diff.Truncated = truncated

	// Exact final verification on the complete DiffJobsResponse.
	for {
		sz, err := encodedMessageSize(resp)
		if err != nil {
			return err
		}
		if sz <= limit {
			return nil
		}
		diff.Truncated = true
		switch {
		case len(diff.AddedHosts) > 0:
			diff.AddedHosts = diff.AddedHosts[:len(diff.AddedHosts)-1]
		case len(diff.RemovedHosts) > 0:
			diff.RemovedHosts = diff.RemovedHosts[:len(diff.RemovedHosts)-1]
		case len(diff.ReplacedHosts) > 0:
			diff.ReplacedHosts = diff.ReplacedHosts[:len(diff.ReplacedHosts)-1]
		case len(diff.MetricDrifts) > 0:
			diff.MetricDrifts = diff.MetricDrifts[:len(diff.MetricDrifts)-1]
		case len(diff.PatternChanges) > 0:
			pc := diff.PatternChanges[len(diff.PatternChanges)-1]
			if !shrinkPatternChange(pc) {
				diff.PatternChanges = diff.PatternChanges[:len(diff.PatternChanges)-1]
				if !pc.Unchanged {
					diff.OmittedPatternChanges++
				}
			}
		case len(diff.StatusTransitions) > 0:
			st := diff.StatusTransitions[len(diff.StatusTransitions)-1]
			if !shrinkStatusTransition(st) {
				diff.StatusTransitions = diff.StatusTransitions[:len(diff.StatusTransitions)-1]
			}
		default:
			return failure(connect.CodeResourceExhausted, "JOB_RESPONSE_LIMIT")
		}
	}
}

package mcp

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

type mcpJobDiff struct {
	BaseJobID               string                `json:"base_job_id"`
	TargetJobID             string                `json:"target_job_id"`
	Action                  string                `json:"action"`
	BaseStatus              string                `json:"base_status"`
	TargetStatus            string                `json:"target_status"`
	BaseTotal               uint64                `json:"base_total"`
	TargetTotal             uint64                `json:"target_total"`
	Grouping                string                `json:"grouping"`
	ActionDefinitionChanged bool                  `json:"action_definition_changed"`
	UnchangedHostsCount     uint64                `json:"unchanged_hosts_count"`
	AddedHostsCount         uint64                `json:"added_hosts_count"`
	AddedHosts              []string              `json:"added_hosts"`
	RemovedHostsCount       uint64                `json:"removed_hosts_count"`
	RemovedHosts            []string              `json:"removed_hosts"`
	ReplacedHostsCount      uint64                `json:"replaced_hosts_count"`
	ReplacedHosts           []string              `json:"replaced_hosts"`
	StatusTransitions       []mcpStatusTransition `json:"status_transitions"`
	TotalPatternChanges     uint64                `json:"total_pattern_changes"`
	OmittedPatternChanges   uint64                `json:"omitted_pattern_changes"`
	PatternChanges          []mcpPatternChange    `json:"pattern_changes"`
	MetricDrifts            []mcpMetricDrift      `json:"metric_drifts"`
	PreviewTruncated        bool                  `json:"preview_truncated"`
	Truncated               bool                  `json:"truncated"`
	OutputTrust             string                `json:"output_trust"`
	Hint                    string                `json:"hint"`
}

type mcpStatusTransition struct {
	FromStatus   string   `json:"from_status"`
	ToStatus     string   `json:"to_status"`
	FromExitCode *int32   `json:"from_exit_code,omitempty"`
	ToExitCode   *int32   `json:"to_exit_code,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	HostCount    uint64   `json:"host_count"`
	Hosts        []string `json:"hosts"`
	Degradation  bool     `json:"degradation"`
}

type mcpPatternChange struct {
	BaseSeverity    string   `json:"base_severity,omitempty"`
	TargetSeverity  string   `json:"target_severity,omitempty"`
	HostCount       uint64   `json:"host_count"`
	Hosts           []string `json:"hosts"`
	Unchanged       bool     `json:"unchanged,omitempty"`
	BasePreview     string   `json:"base_preview,omitempty"`
	TargetPreview   string   `json:"target_preview,omitempty"`
	RemovedLines    []string `json:"removed_lines,omitempty"`
	AddedLines      []string `json:"added_lines,omitempty"`
	DiffComputed    bool     `json:"diff_computed"`
	BaseTruncated   bool     `json:"base_truncated,omitempty"`
	TargetTruncated bool     `json:"target_truncated,omitempty"`
}

type mcpMetricDrift struct {
	Label          string   `json:"label"`
	Unit           string   `json:"unit,omitempty"`
	BaseP50        float64  `json:"base_p50"`
	TargetP50      float64  `json:"target_p50"`
	BaseMax        float64  `json:"base_max"`
	TargetMax      float64  `json:"target_max"`
	MaxDelta       float64  `json:"max_delta"`
	MaxDeltaBase   float64  `json:"max_delta_base"`
	MaxDeltaTarget float64  `json:"max_delta_target"`
	MaxDeltaPct    *float64 `json:"max_delta_pct,omitempty"`
	MaxHost        string   `json:"max_host"`
	AffectedHosts  uint64   `json:"affected_hosts"`
	HostCount      uint64   `json:"host_count"`
}

func shortJobIDArgument(args map[string]json.RawMessage, name string) (string, error) {
	var id string
	if decodeField(args, name, &id, true) != nil || !shortJobID.MatchString(id) {
		return "", accessError(connect.CodeInvalidArgument, name+" allowed: short ID returned by action tools, such as job-20261014-0001")
	}
	return id, nil
}

func (s *Service) diffJobs(ctx context.Context, raw json.RawMessage, state *callState) (*ToolResult, error) {
	args, err := fixedArguments(raw, "base_job_id", "target_job_id", "grouping", "only_changed")
	if err != nil {
		return nil, err
	}
	baseID, err := shortJobIDArgument(args, "base_job_id")
	if err != nil {
		return nil, err
	}
	targetID, err := shortJobIDArgument(args, "target_job_id")
	if err != nil {
		return nil, err
	}
	state.jobID = targetID

	grouping := "normalized"
	if _, present := args["grouping"]; present {
		if decodeField(args, "grouping", &grouping, false) != nil || !slices.Contains([]string{"normalized", "exact"}, grouping) {
			return nil, accessError(connect.CodeInvalidArgument, "grouping allowed: normalized, exact")
		}
	}
	onlyChanged := true
	if _, present := args["only_changed"]; present {
		if decodeField(args, "only_changed", &onlyChanged, false) != nil {
			return nil, accessError(connect.CodeInvalidArgument, "only_changed allowed: boolean")
		}
	}

	response, err := s.jobs.DiffJobs(ctx, &v1.DiffJobsRequest{
		BaseJobId:   baseID,
		TargetJobId: targetID,
		Grouping:    grouping,
		OnlyChanged: &onlyChanged,
	})
	if err != nil {
		return nil, err
	}
	return diffJobsResult(response)
}

func nonNilStrings(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	return slices.Clone(in)
}

func jobStatusName(s v1.JobStatus) string {
	return strings.ToLower(strings.TrimPrefix(s.String(), "JOB_STATUS_"))
}

func diffJobsResult(response *v1.DiffJobsResponse) (*ToolResult, error) {
	if response == nil || response.BaseJob == nil || response.TargetJob == nil || response.Diff == nil || response.Diff.OutputTrust != v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED {
		return nil, accessError(connect.CodeUnavailable, "job diff unavailable")
	}
	diff := response.Diff

	transitions := make([]mcpStatusTransition, 0, len(diff.StatusTransitions))
	for _, st := range diff.StatusTransitions {
		if st == nil {
			continue
		}
		var fromEC, toEC *int32
		if st.FromExitCode != nil {
			v := *st.FromExitCode
			fromEC = &v
		}
		if st.ToExitCode != nil {
			v := *st.ToExitCode
			toEC = &v
		}
		transitions = append(transitions, mcpStatusTransition{
			FromStatus:   taskStatus(st.FromStatus),
			ToStatus:     taskStatus(st.ToStatus),
			FromExitCode: fromEC,
			ToExitCode:   toEC,
			Reason:       st.Reason,
			HostCount:    st.HostCount,
			Hosts:        nonNilStrings(st.Hosts),
			Degradation:  st.Degradation,
		})
	}

	patterns := make([]mcpPatternChange, 0, len(diff.PatternChanges))
	for _, pc := range diff.PatternChanges {
		if pc == nil {
			continue
		}
		patterns = append(patterns, mcpPatternChange{
			BaseSeverity:    groupSeverity(pc.BaseSeverity),
			TargetSeverity:  groupSeverity(pc.TargetSeverity),
			HostCount:       pc.HostCount,
			Hosts:           nonNilStrings(pc.Hosts),
			Unchanged:       pc.Unchanged,
			BasePreview:     strings.ToValidUTF8(pc.BasePreview, "\ufffd"),
			TargetPreview:   strings.ToValidUTF8(pc.TargetPreview, "\ufffd"),
			RemovedLines:    slices.Clone(pc.RemovedLines),
			AddedLines:      slices.Clone(pc.AddedLines),
			DiffComputed:    pc.DiffComputed,
			BaseTruncated:   pc.BaseTruncated,
			TargetTruncated: pc.TargetTruncated,
		})
	}

	drifts := make([]mcpMetricDrift, 0, len(diff.MetricDrifts))
	for _, d := range diff.MetricDrifts {
		if d == nil ||
			!isFiniteFloat(d.BaseP50) || !isFiniteFloat(d.TargetP50) ||
			!isFiniteFloat(d.BaseMax) || !isFiniteFloat(d.TargetMax) ||
			!isFiniteFloat(d.MaxDelta) || !isFiniteFloat(d.MaxDeltaBase) || !isFiniteFloat(d.MaxDeltaTarget) {
			continue
		}
		var maxDeltaPct *float64
		if d.MaxDeltaPct != nil && isFiniteFloat(*d.MaxDeltaPct) {
			v := *d.MaxDeltaPct
			maxDeltaPct = &v
		}
		drifts = append(drifts, mcpMetricDrift{
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

	out := mcpJobDiff{
		BaseJobID:               response.BaseJob.JobId,
		TargetJobID:             response.TargetJob.JobId,
		Action:                  response.TargetJob.Action,
		BaseStatus:              jobStatusName(response.BaseJob.Status),
		TargetStatus:            jobStatusName(response.TargetJob.Status),
		BaseTotal:               response.BaseJob.TotalTasks,
		TargetTotal:             response.TargetJob.TotalTasks,
		Grouping:                diff.Grouping,
		ActionDefinitionChanged: diff.ActionDefinitionChanged,
		UnchangedHostsCount:     diff.UnchangedHostsCount,
		AddedHostsCount:         diff.AddedHostsCount,
		AddedHosts:              nonNilStrings(diff.AddedHosts),
		RemovedHostsCount:       diff.RemovedHostsCount,
		RemovedHosts:            nonNilStrings(diff.RemovedHosts),
		ReplacedHostsCount:      diff.ReplacedHostsCount,
		ReplacedHosts:           nonNilStrings(diff.ReplacedHosts),
		StatusTransitions:       transitions,
		TotalPatternChanges:     diff.TotalPatternChanges,
		OmittedPatternChanges:   diff.OmittedPatternChanges,
		PatternChanges:          patterns,
		MetricDrifts:            drifts,
		PreviewTruncated:        diff.PreviewTruncated,
		Truncated:               diff.Truncated,
		OutputTrust:             "untrusted",
		Hint:                    "Use jobs_get(job_id, host) to inspect complete output on specific hosts. Derived labels and units in metric_drifts come from untrusted host output.",
	}

	result, size, err := toolResult(out)
	if err != nil {
		return nil, err
	}
	if size <= resultByteLimit {
		return result, nil
	}

	// Strictly enforce the 32 KiB MCP result budget (including structuredContent,
	// text copy and _meta) by trimming lowest-priority fields first while
	// preserving all exact counts.
	out.Truncated = true

	trimHostSlice := func(target *[]string) (*ToolResult, bool, error) {
		items := *target
		if len(items) == 0 {
			return nil, false, nil
		}
		// Check whether clearing the whole list is enough to fit; if so, binary
		// search for the largest complete prefix that stays within resultByteLimit.
		*target = []string{}
		emptyRes, emptySize, err := toolResult(out)
		if err != nil {
			return nil, false, err
		}
		if emptySize > resultByteLimit {
			return nil, false, nil
		}
		best := emptyRes
		low, high := 1, len(items)
		for low <= high {
			mid := low + (high-low)/2
			*target = items[:mid]
			res, sz, err := toolResult(out)
			if err != nil {
				return nil, false, err
			}
			if sz <= resultByteLimit {
				best = res
				low = mid + 1
			} else {
				high = mid - 1
			}
		}
		return best, true, nil
	}

	for _, list := range []*[]string{&out.AddedHosts, &out.RemovedHosts, &out.ReplacedHosts} {
		res, fitted, err := trimHostSlice(list)
		if err != nil {
			return nil, err
		}
		if fitted {
			return res, nil
		}
	}

	for {
		result, size, err = toolResult(out)
		if err != nil {
			return nil, err
		}
		if size <= resultByteLimit {
			return result, nil
		}
		switch {
		case len(out.MetricDrifts) > 0:
			out.MetricDrifts = out.MetricDrifts[:len(out.MetricDrifts)-1]
		case len(out.PatternChanges) > 0:
			pc := &out.PatternChanges[len(out.PatternChanges)-1]
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
				pc.Hosts = []string{}
			default:
				dropped := out.PatternChanges[len(out.PatternChanges)-1]
				out.PatternChanges = out.PatternChanges[:len(out.PatternChanges)-1]
				if !dropped.Unchanged {
					out.OmittedPatternChanges++
				}
			}
		case len(out.StatusTransitions) > 0:
			st := &out.StatusTransitions[len(out.StatusTransitions)-1]
			switch {
			case len(st.Hosts) > 2:
				st.Hosts = st.Hosts[:2]
			case len(st.Hosts) > 0:
				st.Hosts = []string{}
			default:
				out.StatusTransitions = out.StatusTransitions[:len(out.StatusTransitions)-1]
			}
		default:
			return nil, accessError(connect.CodeResourceExhausted, "job diff exceeds 32KB")
		}
	}
}

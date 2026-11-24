package job

import (
	"context"
	"slices"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/cluster"
	"github.com/liubing0806/allowops/internal/store"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// PreviewSource is the replaceable boundary for reading output previews stored by other instances (design A23).
// Implementations must return only redacted, filtered, bounded previews.
type PreviewSource interface {
	Load(context.Context, string) ([]Preview, error)
}

type Preview struct {
	Task                   *v1.Task
	Stdout, Stderr         []byte
	StdoutHash, StderrHash []byte
	StdoutSize, StderrSize uint64
}

type DatabasePreviews struct{ Store *store.Store }

func (p *DatabasePreviews) Load(ctx context.Context, id string) ([]Preview, error) {
	return listJobTaskPreviews(ctx, p.Store.Pool, id)
}

func (s *Service) summary(ctx context.Context, j *v1.Job, f string, grouping cluster.GroupingMode) (*v1.JobSummary, error) {
	result := &v1.JobSummary{OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED}
	if _, _, err := s.authorize(ctx, j, authz.ViewOutput, false, ""); err != nil {
		if connect.CodeOf(err) == connect.CodePermissionDenied {
			return result, nil
		}
		return nil, err
	}
	if grouping == cluster.GroupingNormalized {
		release, err := s.acquireAnalysis(ctx)
		if err != nil {
			return nil, err
		}
		defer release()
	}
	items, err := s.Previews.Load(ctx, j.JobId)
	if err != nil {
		return nil, err
	}
	groupPreviewsWithMode(result, items, f, grouping)
	if err := trimSummaryResponse(j, result, ResponseBytes); err != nil {
		return nil, err
	}
	return result, nil
}

// groupPreviews groups tasks in exact mode with unified Anomaly-First ranking.
func groupPreviews(result *v1.JobSummary, items []Preview, f string) {
	groupPreviewsWithMode(result, items, f, cluster.GroupingExact)
}

func groupPreviewsWithMode(result *v1.JobSummary, items []Preview, f string, grouping cluster.GroupingMode) {
	inputs := previewsToTaskInputs(items)
	clustered := cluster.Cluster(inputs, cluster.ClusterOptions{
		Grouping: grouping,
		Detailed: f == "detailed",
	})
	mapped := clusterResultToSummary(clustered)
	result.Groups = mapped.Groups
	result.OfflineHosts = mapped.OfflineHosts
	result.OutputTrust = mapped.OutputTrust
	result.Truncated = mapped.Truncated
	result.Grouping = mapped.Grouping
	result.Ranking = mapped.Ranking
	result.TotalGroups = mapped.TotalGroups
	result.OmittedGroups = mapped.OmittedGroups
	result.FoldedNormalHosts = mapped.FoldedNormalHosts
	result.OmittedHosts = mapped.OmittedHosts
	result.UnfinishedHostsCount = mapped.UnfinishedHostsCount
}

func previewsToTaskInputs(items []Preview) []cluster.TaskInput {
	inputs := make([]cluster.TaskInput, len(items))
	for i, p := range items {
		var hostID, hostname, reason string
		var status v1.TaskStatus
		var exitCode *int32
		var resultTruncated bool
		if p.Task != nil {
			hostID = p.Task.HostId
			hostname = p.Task.Hostname
			if p.Task.Result != nil {
				status = p.Task.Result.Status
				exitCode = p.Task.Result.ExitCode
				reason = p.Task.Result.Reason
				resultTruncated = p.Task.Result.Truncated
			}
		}
		inputs[i] = cluster.TaskInput{
			HostID:          hostID,
			Hostname:        hostname,
			Status:          protoToClusterStatus(status),
			ExitCode:        exitCode,
			Reason:          reason,
			ResultTruncated: resultTruncated,
			Stdout:          p.Stdout,
			Stderr:          p.Stderr,
			StdoutHash:      p.StdoutHash,
			StderrHash:      p.StderrHash,
			StdoutSize:      p.StdoutSize,
			StderrSize:      p.StderrSize,
		}
	}
	return inputs
}

func clusterResultToSummary(res cluster.ClusterResult) *v1.JobSummary {
	groups := make([]*v1.OutputGroup, 0, len(res.Groups))
	for _, g := range res.Groups {
		var variances []*v1.MetricVariance
		if len(g.Variances) > 0 {
			variances = make([]*v1.MetricVariance, 0, len(g.Variances))
			for _, mv := range g.Variances {
				variances = append(variances, &v1.MetricVariance{
					Label:        mv.Label,
					Unit:         mv.Unit,
					Min:          mv.Min,
					P50:          mv.P50,
					P95:          mv.P95,
					Max:          mv.Max,
					MinHost:      mv.MinHost,
					MaxHost:      mv.MaxHost,
					OutlierHosts: slices.Clone(mv.OutlierHosts),
				})
			}
		}
		groups = append(groups, &v1.OutputGroup{
			ExitCode:       g.ExitCode,
			StdoutSha256:   g.StdoutHash,
			StderrSha256:   g.StderrHash,
			HostCount:      g.HostCount,
			Hosts:          slices.Clone(g.Hosts),
			Stdout:         g.Stdout,
			Stderr:         g.Stderr,
			Truncated:      g.Truncated,
			Reason:         g.Reason,
			Severity:       clusterToProtoSeverity(g.Severity),
			AnomalyReason:  g.AnomalyReason,
			TemplateSha256: g.TemplateHash,
			TemplateStdout: g.TemplateStdout,
			TemplateStderr: g.TemplateStderr,
			Variances:      variances,
		})
	}
	return &v1.JobSummary{
		Groups:               groups,
		OfflineHosts:         slices.Clone(res.OfflineHosts),
		OutputTrust:          v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED,
		Truncated:            res.Truncated,
		Grouping:             string(res.Grouping),
		Ranking:              res.Ranking,
		TotalGroups:          res.TotalGroups,
		OmittedGroups:        0,
		FoldedNormalHosts:    res.FoldedNormalHosts,
		OmittedHosts:         0,
		UnfinishedHostsCount: res.UnfinishedHostsCount,
	}
}

func protoToClusterStatus(s v1.TaskStatus) cluster.TaskStatus {
	switch s {
	case v1.TaskStatus_TASK_STATUS_PENDING:
		return cluster.StatusPending
	case v1.TaskStatus_TASK_STATUS_RUNNING:
		return cluster.StatusRunning
	case v1.TaskStatus_TASK_STATUS_SUCCEEDED:
		return cluster.StatusSucceeded
	case v1.TaskStatus_TASK_STATUS_FAILED:
		return cluster.StatusFailed
	case v1.TaskStatus_TASK_STATUS_TIMEOUT:
		return cluster.StatusTimeout
	case v1.TaskStatus_TASK_STATUS_OFFLINE:
		return cluster.StatusOffline
	case v1.TaskStatus_TASK_STATUS_SKIPPED:
		return cluster.StatusSkipped
	case v1.TaskStatus_TASK_STATUS_CANCELLED:
		return cluster.StatusCancelled
	case v1.TaskStatus_TASK_STATUS_UNSUPPORTED:
		return cluster.StatusUnsupported
	default:
		return cluster.StatusUnspecified
	}
}

func clusterToProtoStatus(s cluster.TaskStatus) v1.TaskStatus {
	switch s {
	case cluster.StatusPending:
		return v1.TaskStatus_TASK_STATUS_PENDING
	case cluster.StatusRunning:
		return v1.TaskStatus_TASK_STATUS_RUNNING
	case cluster.StatusSucceeded:
		return v1.TaskStatus_TASK_STATUS_SUCCEEDED
	case cluster.StatusFailed:
		return v1.TaskStatus_TASK_STATUS_FAILED
	case cluster.StatusTimeout:
		return v1.TaskStatus_TASK_STATUS_TIMEOUT
	case cluster.StatusOffline:
		return v1.TaskStatus_TASK_STATUS_OFFLINE
	case cluster.StatusSkipped:
		return v1.TaskStatus_TASK_STATUS_SKIPPED
	case cluster.StatusCancelled:
		return v1.TaskStatus_TASK_STATUS_CANCELLED
	case cluster.StatusUnsupported:
		return v1.TaskStatus_TASK_STATUS_UNSUPPORTED
	default:
		return v1.TaskStatus_TASK_STATUS_UNSPECIFIED
	}
}

func clusterToProtoSeverity(s cluster.Severity) v1.GroupSeverity {
	switch s {
	case cluster.SeverityFailure:
		return v1.GroupSeverity_GROUP_SEVERITY_FAILURE
	case cluster.SeverityAnomaly:
		return v1.GroupSeverity_GROUP_SEVERITY_ANOMALY
	case cluster.SeverityNormal:
		return v1.GroupSeverity_GROUP_SEVERITY_NORMAL
	default:
		return v1.GroupSeverity_GROUP_SEVERITY_UNSPECIFIED
	}
}

func encodedMessageSize(m proto.Message) (int, error) {
	raw, err := protojson.Marshal(m)
	if err != nil {
		return 0, err
	}
	return max(len(raw), proto.Size(m)), nil
}

// jsonStringEncodedSize returns an upper bound on the encoded byte length of a
// single string entry inside a JSON array or protobuf repeated string field.
func jsonStringEncodedSize(s string) int {
	n := len(s) + 2 // surrounding quotes
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\' || c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t':
			n++
		case c < 0x20 || c == '<' || c == '>' || c == '&':
			n += 5 // \u00XX
		}
	}
	return n
}

func shrinkOutputGroup(g *v1.OutputGroup) bool {
	switch {
	case len(g.Hosts) > 2:
		g.Hosts = g.Hosts[:2]
	case len(g.Variances) > 0:
		g.Variances = g.Variances[:len(g.Variances)-1]
	case g.TemplateStderr != "":
		g.TemplateStderr = ""
		g.Truncated = true
	case g.TemplateStdout != "":
		g.TemplateStdout = ""
		g.Truncated = true
	case g.Stderr != "":
		g.Stderr = ""
		g.Truncated = true
	case g.Stdout != "":
		g.Stdout = ""
		g.Truncated = true
	default:
		return false
	}
	return true
}

func recomputeFoldedNormalHosts(result *v1.JobSummary, omittedNormalHosts uint64) {
	folded := omittedNormalHosts
	for _, g := range result.Groups {
		if g.Severity == v1.GroupSeverity_GROUP_SEVERITY_NORMAL && g.HostCount > uint64(len(g.Hosts)) {
			folded += g.HostCount - uint64(len(g.Hosts))
		}
	}
	result.FoldedNormalHosts = folded
}

// trimSummaryResponse enforces ResponseBytes (32 KiB) on the full GetJobResponse
// (both protojson and binary protobuf) in linear O(G) time while maintaining
// strict host conservation across Groups, OfflineHosts, UnfinishedHostsCount,
// and OmittedHosts.
func trimSummaryResponse(j *v1.Job, result *v1.JobSummary, limit int) error {
	response := &v1.GetJobResponse{Job: j, Summary: result}

	// Fast path for small summaries that already fit in one shot.
	if len(result.Groups) <= 16 && len(result.OfflineHosts) <= 64 {
		sz, err := encodedMessageSize(response)
		if err != nil {
			return err
		}
		if sz <= limit {
			return nil
		}
	}

	allGroups := result.Groups
	allOffline := result.OfflineHosts

	var totalGroupHosts uint64
	for _, g := range allGroups {
		totalGroupHosts += g.HostCount
	}
	maxHosts := totalGroupHosts + uint64(len(allOffline))

	// Measure empty-summary baseline with worst-case truncation metadata fields.
	baseSummary := &v1.JobSummary{
		OutputTrust:          result.OutputTrust,
		Truncated:            true,
		Grouping:             result.Grouping,
		Ranking:              result.Ranking,
		TotalGroups:          result.TotalGroups,
		OmittedGroups:        uint64(len(allGroups)),
		FoldedNormalHosts:    maxHosts,
		OmittedHosts:         maxHosts,
		UnfinishedHostsCount: result.UnfinishedHostsCount,
	}
	baseSize, err := encodedMessageSize(&v1.GetJobResponse{Job: j, Summary: baseSummary})
	if err != nil {
		return err
	}

	// Reserve small structural overhead for "groups":[] and "offlineHosts":[] wrappers.
	used := baseSize + 48
	truncated := result.Truncated
	var omittedGroups, omittedHosts, omittedNormalHosts uint64

	keptGroups := make([]*v1.OutputGroup, 0, min(len(allGroups), 32))
	omitStart := len(allGroups)

	for i, g := range allGroups {
		gSize, err := encodedMessageSize(g)
		if err != nil {
			return err
		}
		if used+gSize+4 <= limit {
			keptGroups = append(keptGroups, g)
			used += gSize + 4
			continue
		}

		// Boundary group: try deterministic step-down reductions before omitting.
		truncated = true
		fitted := false
		for shrinkOutputGroup(g) {
			gSize, err = encodedMessageSize(g)
			if err != nil {
				return err
			}
			if used+gSize+4 <= limit {
				fitted = true
				break
			}
		}
		if fitted {
			keptGroups = append(keptGroups, g)
			used += gSize + 4
			omitStart = i + 1
		} else {
			omitStart = i
		}
		break
	}

	for k := omitStart; k < len(allGroups); k++ {
		omittedGroups++
		omittedHosts += allGroups[k].HostCount
		if allGroups[k].Severity == v1.GroupSeverity_GROUP_SEVERITY_NORMAL {
			omittedNormalHosts += allGroups[k].HostCount
		}
	}

	keptOffline := make([]string, 0, min(len(allOffline), 64))
	for i, h := range allOffline {
		hSize := jsonStringEncodedSize(h) + 3
		if used+hSize > limit {
			truncated = true
			omittedHosts += uint64(len(allOffline) - i)
			break
		}
		keptOffline = append(keptOffline, h)
		used += hSize
	}

	result.Groups = keptGroups
	result.OfflineHosts = keptOffline
	result.Truncated = truncated
	result.OmittedGroups = omittedGroups
	result.OmittedHosts = omittedHosts
	recomputeFoldedNormalHosts(result, omittedNormalHosts)

	// Exact final verification on the full GetJobResponse; micro-adjust tail if needed.
	for {
		sz, err := encodedMessageSize(response)
		if err != nil {
			return err
		}
		if sz <= limit {
			return nil
		}
		result.Truncated = true
		if n := len(result.OfflineHosts); n > 0 {
			result.OfflineHosts = result.OfflineHosts[:n-1]
			result.OmittedHosts++
			continue
		}
		if n := len(result.Groups); n > 0 {
			g := result.Groups[n-1]
			if !shrinkOutputGroup(g) {
				result.Groups = result.Groups[:n-1]
				result.OmittedGroups++
				result.OmittedHosts += g.HostCount
				if g.Severity == v1.GroupSeverity_GROUP_SEVERITY_NORMAL {
					omittedNormalHosts += g.HostCount
				}
			}
			recomputeFoldedNormalHosts(result, omittedNormalHosts)
			continue
		}
		return failure(connect.CodeResourceExhausted, "JOB_RESPONSE_LIMIT")
	}
}

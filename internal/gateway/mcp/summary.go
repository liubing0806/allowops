package mcp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"slices"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"google.golang.org/protobuf/proto"
)

type summaryCursor struct {
	Snapshot string `json:"snapshot"`
	Offset   int    `json:"offset"`
}

type summaryItem struct{ group, host, offline int }

// reasonHints are gateway-owned texts for builtin reason codes (log search
// design 6.7). Hosts send only the code; PATH_OUTSIDE_ROOTS has no hint.
var reasonHints = map[string]string{
	"SOURCE_UNKNOWN":     "The source name is not in the catalog; call log_sources to list available source names.",
	"SOURCE_NO_FILES":    "The source's glob matched no files on this host; call log_sources to check its files.",
	"SOURCE_UNSUPPORTED": "This host cannot read the source: the container log path is outside every mount and the storage driver is not overlay2, or the container's logging driver does not support reading.",
	"SOURCE_UNAVAILABLE": "The source's container is not found or the Docker API is unreachable on this host; call log_sources to check the source status.",
	"WINDOW_TOO_LARGE":   "until - since exceeds the source's max_window; narrow the time range.",
	"TIME_INVALID":       "since/until must be RFC 3339 (2026-10-23T14:45:00+08:00) or a relative duration (30m, 2h), and since must be earlier than until.",
	"TIMESTAMP_UNPARSED": "No timestamp could be parsed in files within the time range; retry without since/until, or check the source's timestamp.layouts.",
	"PATTERN_INVALID":    "The pattern is not valid RE2 syntax; fix the regular expression or use a fixed-string match.",
	"CURSOR_INVALID":     "The cursor does not match this source or request parameters; repeat the previous parameters unchanged or restart without cursor.",
	"CURSOR_EXPIRED":     "The cursor's file was rotated away; restart without cursor, using the last record time as the new until (desc) or since (asc).",
	"LEVEL_UNSUPPORTED":  "The source declares no level rule; omit level, or match the level text with pattern.",
}

// Slice already-authorized job-summary groups for transport (design G57, P6); never group tasks or
// read additional job data. Detailed pages may continue the hosts of one group.
func nativeSummaryResult(scope string, j *v1.Job, summary *v1.JobSummary, format, cursor string) (*ToolResult, error) {
	if scope == "" || j == nil || summary == nil || summary.OutputTrust != v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED {
		return nil, accessError(connect.CodeUnavailable, "job summary unavailable")
	}
	if !slices.Contains([]string{"concise", "detailed"}, format) {
		return nil, accessError(connect.CodeInvalidArgument, "response_format allowed: concise, detailed")
	}
	summary = sanitizeSummaryForJSON(summary)
	binding, err := json.Marshal(struct {
		Scope, Format string
		Job           *v1.Job
		Summary       *v1.JobSummary
	}{scope, format, j, summary})
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(binding)
	page := &summaryPage{job: j, summary: summary, format: format, snapshot: hex.EncodeToString(hash[:])}
	if page.items, err = summaryItems(summary, format); err != nil {
		return nil, err
	}
	if cursor != "" {
		if page.start, err = page.startOffset(cursor); err != nil {
			return nil, err
		}
	}
	return page.fit()
}

// summaryItems lists the units a page can end between: one group, or one host
// of a group in detailed format, then each offline host.
func summaryItems(summary *v1.JobSummary, format string) ([]summaryItem, error) {
	items := []summaryItem{}
	for i, g := range summary.Groups {
		if g == nil {
			return nil, accessError(connect.CodeUnavailable, "job group unavailable")
		}
		if format == "detailed" && len(g.Hosts) > 0 {
			for host := range g.Hosts {
				items = append(items, summaryItem{group: i, host: host, offline: -1})
			}
		} else {
			items = append(items, summaryItem{group: i, host: -1, offline: -1})
		}
	}
	for i := range summary.OfflineHosts {
		items = append(items, summaryItem{group: -1, host: -1, offline: i})
	}
	return items, nil
}

// summaryPage holds what is needed to render one page of items[start:end].
type summaryPage struct {
	job      *v1.Job
	summary  *v1.JobSummary
	format   string
	snapshot string
	items    []summaryItem
	start    int
}

// startOffset decodes a next_cursor and checks it against this snapshot.
func (p *summaryPage) startOffset(cursor string) (int, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
	if len(cursor) > 256 || err != nil {
		return 0, invalidArguments(errors.New("invalid summary cursor; restart without next_cursor"))
	}
	object, err := argumentObject(decoded)
	var c summaryCursor
	if err != nil || len(object) != 2 || json.Unmarshal(decoded, &c) != nil || c.Snapshot != p.snapshot || c.Offset <= 0 || c.Offset >= len(p.items) {
		return 0, invalidArguments(errors.New("summary cursor does not match identity, job, format or P6 snapshot; restart without next_cursor"))
	}
	return c.Offset, nil
}

// fit renders the longest page that stays within resultByteLimit. When even one
// item is too large, it halves the stdout/stderr/template preview until it fits,
// and drops variances on the final fallback round if needed.
func (p *summaryPage) fit() (*ToolResult, error) {
	if len(p.items) == 0 {
		result, size, err := p.render(0, groupByteLimit, true)
		if size > resultByteLimit {
			return nil, accessError(connect.CodeResourceExhausted, "job metadata exceeds 32KB")
		}
		return result, err
	}
	var best *ToolResult
	for end := p.start + 1; end <= len(p.items); end++ {
		result, size, err := p.render(end, groupByteLimit, true)
		if err != nil {
			return nil, err
		}
		if size <= resultByteLimit {
			best = result
			continue
		}
		if best != nil {
			return best, nil
		}
		for limit := groupByteLimit / 2; ; limit /= 2 {
			result, size, err = p.render(end, limit, true)
			if err != nil {
				return nil, err
			}
			if size <= resultByteLimit {
				return result, nil
			}
			if limit == 0 {
				result, size, err = p.render(end, 0, false)
				if err != nil {
					return nil, err
				}
				if size <= resultByteLimit {
					return result, nil
				}
				return nil, accessError(connect.CodeResourceExhausted, "job metadata exceeds 32KB")
			}
		}
	}
	return best, nil
}

// render builds the result for items[start:end] and returns its encoded size.
func (p *summaryPage) render(end, previewLimit int, includeVariances bool) (*ToolResult, int, error) {
	data := jobMetadata(p.job)
	data["groups"] = []map[string]any{}
	data["offline_hosts"] = []string{}
	data["truncated"] = p.summary.Truncated
	data["hint"] = "Use jobs_get(job_id, host) for complete output; use next_cursor for remaining supplied groups. P6 may already have truncated the source summary."
	if p.summary.Grouping != "" {
		data["grouping"] = p.summary.Grouping
	}
	if p.summary.Ranking != "" {
		data["ranking"] = p.summary.Ranking
	}
	if p.summary.TotalGroups > 0 {
		data["total_groups"] = p.summary.TotalGroups
	}
	if p.summary.OmittedGroups > 0 {
		data["omitted_groups"] = p.summary.OmittedGroups
	}
	if p.summary.OmittedHosts > 0 {
		data["omitted_hosts"] = p.summary.OmittedHosts
	}
	if p.summary.FoldedNormalHosts > 0 {
		data["folded_normal_hosts"] = p.summary.FoldedNormalHosts
	}
	if p.summary.UnfinishedHostsCount > 0 {
		data["unfinished_hosts_count"] = p.summary.UnfinishedHostsCount
	}
	groups := []map[string]any{}
	lastGroup := -1
	for _, item := range p.items[p.start:end] {
		if item.offline >= 0 {
			data["offline_hosts"] = append(data["offline_hosts"].([]string), p.summary.OfflineHosts[item.offline])
			continue
		}
		source := p.summary.Groups[item.group]
		if item.group != lastGroup {
			g, shortened := p.groupPreview(source, previewLimit, includeVariances)
			if shortened {
				data["truncated"] = true
			}
			groups = append(groups, g)
			lastGroup = item.group
		}
		if p.format == "detailed" && item.host >= 0 {
			g := groups[len(groups)-1]
			g["hosts"] = append(g["hosts"].([]string), source.Hosts[item.host])
		}
	}
	data["groups"] = groups
	if end < len(p.items) {
		raw, _ := json.Marshal(summaryCursor{Snapshot: p.snapshot, Offset: end})
		data["next_cursor"] = base64.RawURLEncoding.EncodeToString(raw)
	}
	return toolResult(data)
}

type mcpMetricVariance struct {
	Label        string   `json:"label"`
	Unit         string   `json:"unit,omitempty"`
	Min          float64  `json:"min"`
	P50          float64  `json:"p50"`
	P95          float64  `json:"p95"`
	Max          float64  `json:"max"`
	MinHost      string   `json:"min_host"`
	MaxHost      string   `json:"max_host"`
	OutlierHosts []string `json:"outlier_hosts,omitempty"`
}

func groupSeverity(s v1.GroupSeverity) string {
	switch s {
	case v1.GroupSeverity_GROUP_SEVERITY_FAILURE:
		return "failure"
	case v1.GroupSeverity_GROUP_SEVERITY_ANOMALY:
		return "anomaly"
	case v1.GroupSeverity_GROUP_SEVERITY_NORMAL:
		return "normal"
	default:
		return ""
	}
}

func isFiniteFloat(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}

func sanitizeSummaryForJSON(summary *v1.JobSummary) *v1.JobSummary {
	hasNonFinite := false
	for _, g := range summary.Groups {
		if g == nil {
			continue
		}
		for _, mv := range g.Variances {
			if mv != nil && (!isFiniteFloat(mv.Min) || !isFiniteFloat(mv.P50) || !isFiniteFloat(mv.P95) || !isFiniteFloat(mv.Max)) {
				hasNonFinite = true
				break
			}
		}
		if hasNonFinite {
			break
		}
	}
	if !hasNonFinite {
		return summary
	}
	cloned := proto.Clone(summary).(*v1.JobSummary)
	for _, g := range cloned.Groups {
		if g == nil || len(g.Variances) == 0 {
			continue
		}
		kept := make([]*v1.MetricVariance, 0, len(g.Variances))
		for _, mv := range g.Variances {
			if mv == nil || !isFiniteFloat(mv.Min) || !isFiniteFloat(mv.P50) || !isFiniteFloat(mv.P95) || !isFiniteFloat(mv.Max) {
				continue
			}
			kept = append(kept, mv)
		}
		g.Variances = kept
	}
	return cloned
}

// groupPreview maps one backend group, sharing previewLimit bytes across
// stdout, stderr, template_stdout and template_stderr. The bool reports whether
// the preview cut any output or dropped variances.
func (p *summaryPage) groupPreview(source *v1.OutputGroup, previewLimit int, includeVariances bool) (map[string]any, bool) {
	rawBudget := previewLimit
	tmplBudget := 0
	if source.TemplateStdout != "" || source.TemplateStderr != "" {
		rawLen := len(source.Stdout) + len(source.Stderr)
		tmplLen := len(source.TemplateStdout) + len(source.TemplateStderr)
		if rawLen+tmplLen <= previewLimit {
			rawBudget = rawLen
			tmplBudget = tmplLen
		} else {
			half := previewLimit / 2
			rawBudget = min(rawLen, half)
			tmplBudget = min(tmplLen, half)
			if rem := previewLimit - rawBudget - tmplBudget; rem > 0 {
				if rawLen > rawBudget {
					add := min(rem, rawLen-rawBudget)
					rawBudget += add
					rem -= add
				}
				if rem > 0 && tmplLen > tmplBudget {
					tmplBudget += min(rem, tmplLen-tmplBudget)
				}
			}
		}
	}
	stdout := textPrefix(source.Stdout, rawBudget)
	stderr := textPrefix(source.Stderr, max(0, rawBudget-len(stdout)))
	tmplStdout := textPrefix(source.TemplateStdout, tmplBudget)
	tmplStderr := textPrefix(source.TemplateStderr, max(0, tmplBudget-len(tmplStdout)))
	shortened := len(stdout) < len(source.Stdout) ||
		len(stderr) < len(source.Stderr) ||
		len(tmplStdout) < len(source.TemplateStdout) ||
		len(tmplStderr) < len(source.TemplateStderr)
	if !includeVariances && len(source.Variances) > 0 {
		shortened = true
	}
	g := map[string]any{"host_count": source.HostCount, "stdout": stdout, "stderr": stderr, "truncated": source.Truncated || shortened}
	if source.ExitCode != nil {
		g["exit_code"] = *source.ExitCode
	}
	if source.Reason != "" {
		g["reason"] = source.Reason
		if hint := reasonHints[source.Reason]; hint != "" {
			g["hint"] = hint
		}
	}
	if sev := groupSeverity(source.Severity); sev != "" {
		g["severity"] = sev
	}
	if source.AnomalyReason != "" {
		g["anomaly_reason"] = source.AnomalyReason
	}
	if len(source.TemplateSha256) > 0 {
		g["template_sha256"] = hex.EncodeToString(source.TemplateSha256)
	}
	if tmplStdout != "" {
		g["template_stdout"] = tmplStdout
	}
	if tmplStderr != "" {
		g["template_stderr"] = tmplStderr
	}
	if includeVariances && len(source.Variances) > 0 {
		variances := make([]mcpMetricVariance, 0, len(source.Variances))
		for _, mv := range source.Variances {
			if mv == nil || !isFiniteFloat(mv.Min) || !isFiniteFloat(mv.P50) || !isFiniteFloat(mv.P95) || !isFiniteFloat(mv.Max) {
				continue
			}
			variances = append(variances, mcpMetricVariance{
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
		if len(variances) > 0 {
			g["variances"] = variances
		}
	}
	if p.format == "detailed" {
		g["hosts"] = []string{}
	} else {
		g["sample_hosts"] = slices.Clone(source.Hosts[:min(2, len(source.Hosts))])
	}
	return g, shortened
}

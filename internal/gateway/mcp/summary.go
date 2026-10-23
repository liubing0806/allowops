package mcp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

type summaryCursor struct {
	Snapshot string `json:"snapshot"`
	Offset   int    `json:"offset"`
}
type summaryItem struct{ group, host, offline int }

// G57: slice already-authorized P6 groups for transport; never group tasks or
// read additional job data. Detailed pages may continue the hosts of one group.
func nativeSummaryResult(scope string, j *v1.Job, summary *v1.JobSummary, format, cursor string) (*ToolResult, error) {
	if scope == "" || j == nil || summary == nil || summary.OutputTrust != v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED {
		return nil, accessError(connect.CodeUnavailable, "job summary unavailable")
	}
	if !slices.Contains([]string{"concise", "detailed"}, format) {
		return nil, accessError(connect.CodeInvalidArgument, "response_format allowed: concise, detailed")
	}
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
// item is too large, it halves the stdout/stderr preview until it fits.
func (p *summaryPage) fit() (*ToolResult, error) {
	if len(p.items) == 0 {
		result, size, err := p.render(0, groupByteLimit)
		if size > resultByteLimit {
			return nil, accessError(connect.CodeResourceExhausted, "job metadata exceeds 32KB")
		}
		return result, err
	}
	var best *ToolResult
	for end := p.start + 1; end <= len(p.items); end++ {
		result, size, err := p.render(end, groupByteLimit)
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
			result, size, err = p.render(end, limit)
			if err != nil {
				return nil, err
			}
			if size <= resultByteLimit {
				return result, nil
			}
			if limit == 0 {
				return nil, accessError(connect.CodeResourceExhausted, "job metadata exceeds 32KB")
			}
		}
	}
	return best, nil
}

// render builds the result for items[start:end] and returns its encoded size.
func (p *summaryPage) render(end, previewLimit int) (*ToolResult, int, error) {
	data := jobMetadata(p.job)
	data["groups"] = []map[string]any{}
	data["offline_hosts"] = []string{}
	data["truncated"] = p.summary.Truncated
	data["hint"] = "Use jobs_get(job_id, host) for complete output; use next_cursor for remaining supplied groups. P6 may already have truncated the source summary."
	groups := []map[string]any{}
	lastGroup := -1
	for _, item := range p.items[p.start:end] {
		if item.offline >= 0 {
			data["offline_hosts"] = append(data["offline_hosts"].([]string), p.summary.OfflineHosts[item.offline])
			continue
		}
		source := p.summary.Groups[item.group]
		if item.group != lastGroup {
			g, shortened := p.groupPreview(source, previewLimit)
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

// groupPreview maps one backend group, cutting stdout then stderr to previewLimit
// bytes in total. The bool reports whether the preview cut any output.
func (p *summaryPage) groupPreview(source *v1.OutputGroup, previewLimit int) (map[string]any, bool) {
	stdout := textPrefix(source.Stdout, previewLimit)
	stderr := textPrefix(source.Stderr, previewLimit-len(stdout))
	shortened := len(stdout) < len(source.Stdout) || len(stderr) < len(source.Stderr)
	g := map[string]any{"host_count": source.HostCount, "stdout": stdout, "stderr": stderr, "truncated": source.Truncated || shortened}
	if source.ExitCode != nil {
		g["exit_code"] = *source.ExitCode
	}
	if p.format == "detailed" {
		g["hosts"] = []string{}
	} else {
		g["sample_hosts"] = slices.Clone(source.Hosts[:min(2, len(source.Hosts))])
	}
	return g, shortened
}

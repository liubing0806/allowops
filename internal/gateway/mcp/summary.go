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
	snapshot := hex.EncodeToString(hash[:])
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
	start := 0
	if cursor != "" {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
		if len(cursor) > 256 || err != nil {
			return nil, invalidArguments(errors.New("invalid summary cursor; restart without next_cursor"))
		}
		object, err := argumentObject(decoded)
		var c summaryCursor
		if err != nil || len(object) != 2 || json.Unmarshal(decoded, &c) != nil || c.Snapshot != snapshot || c.Offset <= 0 || c.Offset >= len(items) {
			return nil, invalidArguments(errors.New("summary cursor does not match identity, job, format or P6 snapshot; restart without next_cursor"))
		}
		start = c.Offset
	}
	candidate := func(end, previewLimit int) (*ToolResult, int, error) {
		data := jobMetadata(j)
		data["groups"] = []map[string]any{}
		data["offline_hosts"] = []string{}
		data["truncated"] = summary.Truncated
		data["hint"] = "Use jobs_get(job_id, host) for complete output; use next_cursor for remaining supplied groups. P6 may already have truncated the source summary."
		groups := []map[string]any{}
		lastGroup := -1
		for _, item := range items[start:end] {
			if item.offline >= 0 {
				data["offline_hosts"] = append(data["offline_hosts"].([]string), summary.OfflineHosts[item.offline])
				continue
			}
			source := summary.Groups[item.group]
			if item.group != lastGroup {
				stdout := textPrefix(source.Stdout, previewLimit)
				stderr := textPrefix(source.Stderr, previewLimit-len(stdout))
				shortened := len(stdout) < len(source.Stdout) || len(stderr) < len(source.Stderr)
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
				if format == "detailed" {
					g["hosts"] = []string{}
				} else {
					g["sample_hosts"] = slices.Clone(source.Hosts[:min(2, len(source.Hosts))])
				}
				if shortened {
					data["truncated"] = true
				}
				groups = append(groups, g)
				lastGroup = item.group
			}
			if format == "detailed" && item.host >= 0 {
				g := groups[len(groups)-1]
				g["hosts"] = append(g["hosts"].([]string), source.Hosts[item.host])
			}
		}
		data["groups"] = groups
		if end < len(items) {
			raw, _ := json.Marshal(summaryCursor{Snapshot: snapshot, Offset: end})
			data["next_cursor"] = base64.RawURLEncoding.EncodeToString(raw)
		}
		return toolResult(data)
	}
	if len(items) == 0 {
		result, size, err := candidate(0, groupByteLimit)
		if size > resultByteLimit {
			return nil, accessError(connect.CodeResourceExhausted, "job metadata exceeds 32KB")
		}
		return result, err
	}
	var best *ToolResult
	for end := start + 1; end <= len(items); end++ {
		result, size, err := candidate(end, groupByteLimit)
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
			result, size, err = candidate(end, limit)
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

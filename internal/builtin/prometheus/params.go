package prometheus

import (
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/liubing0806/allowops/internal/params"
)

const (
	timeLayout = "2006-01-02T15:04:05Z"
	// maxTimeDigits and maxTimeOffset bound the count in now-<n><unit>, which would overflow time.Duration.
	maxTimeDigits = 6
	maxTimeOffset = 100 * 365 * 24 * time.Hour
	labelPattern  = `^[a-zA-Z_][a-zA-Z0-9_]*$`
	timePattern   = `^(now(-[0-9]{1,6}[smhd])?|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)$`
)

var (
	relativeTime = regexp.MustCompile(`^now-([0-9]{1,` + strconv.Itoa(maxTimeDigits) + `})([smhd])$`)
	absoluteTime = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	labelName    = regexp.MustCompile(labelPattern)
)

// now is replaced by tests.
var now = time.Now

// Params are the per-call parameters. Empty values mean "omitted".
type Params struct {
	Query    string
	Time     string
	Start    string
	End      string
	Step     time.Duration
	Match    []string
	Label    string
	Summary  bool
	RuleType string
}

// Definitions returns the handler-owned parameter definitions of api.
func Definitions(api string) (map[string]params.Definition, error) {
	timeDef := func(description string) params.Definition {
		return params.Definition{Type: params.String, Description: description, Regex: timePattern, MaxLen: 32, Optional: true}
	}
	rangeDefs := func() map[string]params.Definition {
		return map[string]params.Definition{
			"start": timeDef("Start time: now, now-<n><s|m|h|d> or UTC RFC 3339; default now-1h"),
			"end":   timeDef("End time: now, now-<n><s|m|h|d> or UTC RFC 3339; default now"),
		}
	}
	match := func(description string, optional bool) params.Definition {
		return params.Definition{Type: params.StringArray, Description: description, MaxItems: 10, MaxLen: 500, Optional: optional}
	}
	switch api {
	case APIQuery:
		return map[string]params.Definition{
			"query": {Type: params.String, Description: "PromQL expression", MaxLen: 2000},
			"time":  timeDef("Evaluation time: now, now-<n><s|m|h|d> or UTC RFC 3339; default now"),
		}, nil
	case APIQueryRange:
		defs := rangeDefs()
		defs["query"] = params.Definition{Type: params.String, Description: "PromQL expression", MaxLen: 2000}
		start := defs["start"]
		start.Optional = false
		defs["start"] = start
		defs["step"] = params.Definition{Type: params.Duration, Description: "Sampling interval, not below min_step; default derived from max_points", Max: MaxRange.String(), Optional: true}
		defs["summary"] = params.Definition{Type: params.Bool, Description: "Output min, avg, max and last per series instead of every point", Default: false}
		return defs, nil
	case APISeries:
		defs := rangeDefs()
		defs["match"] = match("Series selectors, for example up{job=\"api\"}", false)
		return defs, nil
	case APILabels:
		defs := rangeDefs()
		defs["match"] = match("Series selectors that restrict the labels", true)
		return defs, nil
	case APILabelValues:
		defs := rangeDefs()
		defs["match"] = match("Series selectors that restrict the values", true)
		defs["label"] = params.Definition{Type: params.String, Description: "Label name; __name__ lists metric names", Regex: labelPattern, MaxLen: 128}
		return defs, nil
	case APIAlerts, APITargets:
		return map[string]params.Definition{}, nil
	case APIRules:
		return map[string]params.Definition{
			"rule_type": {Type: params.Enum, Description: "Rule type filter", Values: []string{"alert", "record"}, Optional: true},
		}, nil
	}
	return nil, fmt.Errorf("unsupported prometheus api %q", api)
}

// ParseTime resolves now, now-<n><s|m|h|d> or a UTC RFC 3339 time in whole
// seconds. Offsets other than Z and fractional seconds are rejected.
func ParseTime(s string, at time.Time) (time.Time, error) {
	base := at.UTC().Truncate(time.Second)
	if s == "now" {
		return base, nil
	}
	if m := relativeTime.FindStringSubmatch(s); m != nil {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		unit := map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[m[2]]
		if n > int64(maxTimeOffset/unit) {
			return time.Time{}, fmt.Errorf("time offset %q exceeds the supported range", s)
		}
		return base.Add(-time.Duration(n) * unit), nil
	}
	if absoluteTime.MatchString(s) {
		if t, err := time.Parse(timeLayout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid time %q; allowed: now, now-<n><s|m|h|d> or UTC RFC 3339 such as 2026-10-23T03:12:00Z", s)
}

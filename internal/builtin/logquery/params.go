package logquery

import "github.com/liubing0806/allowops/internal/params"

// Parameters returns the caller parameters of the configured mode. Phase 2
// modes add their own cases here.
func Parameters(cfg Config) map[string]params.Definition {
	cfg = cfg.withDefaults()
	switch cfg.Mode {
	case ModeSearch:
		names := cfg.SourceNames()
		source := params.Definition{Type: params.Enum, Description: "Log source name from log_sources", Values: names}
		if len(names) == 1 {
			source.Default = names[0]
		}
		one, limit := int64(1), min(DefaultLimit, cfg.MaxPageRecords)
		timeText := `^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+(Z|[+-][0-9]{2}:[0-9]{2})|[0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$`
		return map[string]params.Definition{
			"source":      source,
			"since":       {Type: params.String, Description: "Start: RFC 3339 time (2026-10-23T14:45:00+08:00) or duration before now (30m, 2h); default until minus 1h", Regex: timeText, MaxLen: 64, Optional: true},
			"until":       {Type: params.String, Description: "End: RFC 3339 time or duration before now; default now", Regex: timeText, MaxLen: 64, Optional: true},
			"pattern":     {Type: params.String, Description: "RE2 pattern matched against the whole record before redaction; omit for all records", MaxLen: MaxPatternLength, Optional: true},
			"fixed":       {Type: params.Bool, Description: "Treat pattern and exclude as literal text", Default: false},
			"exclude":     {Type: params.String, Description: "Drop records matching this pattern", MaxLen: MaxPatternLength, Optional: true},
			"ignore_case": {Type: params.Bool, Description: "Case-insensitive pattern and exclude", Default: false},
			"limit":       {Type: params.Int, Description: "Records per page", Min: &one, Max: cfg.MaxPageRecords, Default: limit},
			"order":       {Type: params.Enum, Description: "desc returns the newest records first", Values: []string{"desc", "asc"}, Default: "desc"},
			"cursor":      {Type: params.String, Description: "next_cursor of the previous page; other parameters must be unchanged", Regex: `^[A-Za-z0-9_-]+$`, MaxLen: 4096, Optional: true},
		}
	default:
		return map[string]params.Definition{}
	}
}

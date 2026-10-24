package logquery

import (
	"strings"

	"github.com/liubing0806/allowops/internal/params"
)

// Parameters returns the caller parameters of the configured mode.
func Parameters(cfg Config) map[string]params.Definition {
	cfg = cfg.withDefaults()
	switch cfg.Mode {
	case ModeSearch, ModeExport:
		names := cfg.SourceNames()
		source := params.Definition{Type: params.Enum, Description: "Log source name from log_sources", Values: names}
		if len(names) == 1 {
			source.Default = names[0]
		}
		one, limit := int64(1), min(DefaultLimit, cfg.MaxPageRecords)
		timeText := `^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+(Z|[+-][0-9]{2}:[0-9]{2})|[0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$`
		defs := map[string]params.Definition{
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
		if cfg.anyLevel() {
			defs["level"] = params.Definition{Type: params.StringArray, Description: "Keep records whose first line has one of these levels (ERROR, WARN, INFO, DEBUG); only for sources with a level rule",
				Regex: "^(" + strings.Join(Levels, "|") + ")$", MaxItems: len(Levels), MaxLen: 5, Optional: true}
		}
		if cfg.Mode == ModeExport {
			// Export is oldest first; max_output usually ends a page first.
			delete(defs, "order")
			maxExport := int64(MaxExportRecords)
			defs["limit"] = params.Definition{Type: params.Int, Description: "Records per page; the page also ends at max_output", Min: &one, Max: maxExport, Default: maxExport}
			defs["cursor"] = params.Definition{Type: params.String, Description: "next_cursor from the trailer line of the previous page; other parameters must be unchanged", Regex: `^[A-Za-z0-9_-]+$`, MaxLen: 4096, Optional: true}
		}
		return defs
	case ModeStats:
		return statsParameters(cfg)
	case ModePatterns:
		return patternsParameters(cfg)
	default:
		return map[string]params.Definition{}
	}
}

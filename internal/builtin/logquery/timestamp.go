package logquery

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// bracketSearch bounds how far into a line the opening bracket may appear.
const bracketSearch = 256

type timeParser struct {
	layouts   []string
	location  *time.Location
	bracketed bool
	// firstField parses the text before the first space, as in the runtime
	// prefix of CRI log lines.
	firstField bool
}

func newTimeParser(ts Timestamp) (*timeParser, error) {
	if len(ts.Layouts) == 0 {
		return nil, errors.New("timestamp.layouts required")
	}
	for _, layout := range ts.Layouts {
		if strings.TrimSpace(layout) == "" || strings.ContainsAny(layout, "\x00\r\n") {
			return nil, errors.New("timestamp.layouts must be nonempty Go time layouts")
		}
	}
	location, err := loadLocation(ts.Timezone)
	if err != nil {
		return nil, err
	}
	return &timeParser{layouts: ts.Layouts, location: location, bracketed: ts.Bracketed}, nil
}

// loadLocation returns the named zone, or the host's local zone for "".
func loadLocation(name string) (*time.Location, error) {
	if name == "" {
		return time.Local, nil
	}
	location, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("timestamp.timezone: %w", err)
	}
	return location, nil
}

// parse reads the timestamp at the start of the line, or inside its first
// [...] when bracketed. Layouts are tried in order.
func (p *timeParser) parse(line string) (time.Time, bool) {
	if p.firstField {
		field, _, _ := strings.Cut(line, " ")
		t, err := time.Parse(time.RFC3339Nano, field)
		return t, err == nil
	}
	if p.bracketed {
		open := strings.IndexByte(line[:min(len(line), bracketSearch)], '[')
		if open < 0 {
			return time.Time{}, false
		}
		end := strings.IndexByte(line[open+1:], ']')
		if end < 0 {
			return time.Time{}, false
		}
		text := line[open+1 : open+1+end]
		for _, layout := range p.layouts {
			if t, err := time.ParseInLocation(layout, text, p.location); err == nil {
				return t, true
			}
		}
		return time.Time{}, false
	}
	for _, layout := range p.layouts {
		if t, ok := p.prefix(layout, line); ok {
			return t, true
		}
	}
	return time.Time{}, false
}

// prefix parses a timestamp at the start of line. Fixed-width layouts match
// at len(layout); variable-width ones (fractional seconds, zone names) are cut
// where time.Parse reports the trailing text.
func (p *timeParser) prefix(layout, line string) (time.Time, bool) {
	if len(line) >= len(layout) {
		if t, err := time.ParseInLocation(layout, line[:len(layout)], p.location); err == nil {
			return t, true
		}
	}
	candidate := line[:min(len(line), len(layout)+16)]
	t, err := time.ParseInLocation(layout, candidate, p.location)
	if err == nil {
		return t, true
	}
	var parseErr *time.ParseError
	if !errors.As(err, &parseErr) || !strings.HasPrefix(parseErr.Message, ": extra text: ") || len(parseErr.ValueElem) >= len(candidate) {
		return time.Time{}, false
	}
	t, err = time.ParseInLocation(layout, candidate[:len(candidate)-len(parseErr.ValueElem)], p.location)
	return t, err == nil
}

// parseTimeRange resolves since/until: RFC 3339 times or positive Go durations
// before now. Omitted until is now; omitted since is until minus one hour.
func parseTimeRange(sinceText, untilText string, now time.Time, maxWindow time.Duration) (time.Time, time.Time, error) {
	until, err := parsePoint(untilText, now)
	if err != nil {
		return time.Time{}, time.Time{}, codeError(CodeTimeInvalid, "until: %v", err)
	}
	since := until.Add(-DefaultRange)
	if sinceText != "" {
		if since, err = parsePoint(sinceText, now); err != nil {
			return time.Time{}, time.Time{}, codeError(CodeTimeInvalid, "since: %v", err)
		}
	}
	return since, until, checkWindow(since, until, maxWindow)
}

func checkWindow(since, until time.Time, maxWindow time.Duration) error {
	if !since.Before(until) {
		return codeError(CodeTimeInvalid, "since %s must be earlier than until %s", since.Format(time.RFC3339), until.Format(time.RFC3339))
	}
	if until.Sub(since) > maxWindow {
		return codeError(CodeWindowTooLarge, "range %s exceeds max_window %s", until.Sub(since), maxWindow)
	}
	return nil
}

func parsePoint(text string, now time.Time) (time.Time, error) {
	if text == "" {
		return now, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, text); err == nil {
		return t, nil
	}
	d, err := time.ParseDuration(text)
	if err != nil || d <= 0 {
		return time.Time{}, fmt.Errorf("%q is neither RFC 3339 (2026-10-23T14:45:00+08:00) nor a positive duration (30m, 2h)", text)
	}
	return now.Add(-d), nil
}

func formatTime(t time.Time, location *time.Location) string {
	return t.In(location).Format(time.RFC3339Nano)
}

package prometheus

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

// formatter writes the TSV output. Every cell is masked first and escaped
// second, so a mask cannot introduce a field or line separator.
type formatter struct {
	api       string
	maxSeries int
	mask      func(string) string

	out       strings.Builder
	truncated bool
	note      string
}

var tsvEscaper = strings.NewReplacer("\\", "\\\\", "\t", `\t`, "\n", `\n`, "\r", `\r`, "\x00", `\0`)

func (f *formatter) header(text string) { f.out.WriteString("# " + text + "\n") }

func (f *formatter) row(cells ...string) {
	for i, cell := range cells {
		if f.mask != nil {
			cell = f.mask(cell)
		}
		if i > 0 {
			f.out.WriteByte('\t')
		}
		f.out.WriteString(tsvEscaper.Replace(cell))
	}
	f.out.WriteByte('\n')
}

// limit returns how many of total results are written and records the
// truncation note. exact is false when the server applied its own limit.
func (f *formatter) limit(total int, exact bool) int {
	if total <= f.maxSeries {
		return total
	}
	of := strconv.Itoa(total)
	if !exact {
		of = "at least " + of
	}
	f.truncated = true
	f.note = fmt.Sprintf("truncated: returned %d of %s results (max_series)\n", f.maxSeries, of)
	return f.maxSeries
}

func (f *formatter) format(data json.RawMessage, summary bool) error {
	switch f.api {
	case APIQuery, APIQueryRange:
		return f.formatQuery(data, summary)
	case APISeries:
		var series []map[string]string
		if err := json.Unmarshal(data, &series); err != nil {
			return err
		}
		for _, labels := range series[:f.limit(len(series), false)] {
			f.row(labelSet(labels))
		}
	case APILabels, APILabelValues:
		var values []string
		if err := json.Unmarshal(data, &values); err != nil {
			return err
		}
		for _, value := range values[:f.limit(len(values), false)] {
			f.row(value)
		}
	case APIAlerts:
		return f.formatAlerts(data)
	case APIRules:
		return f.formatRules(data)
	case APITargets:
		return f.formatTargets(data)
	}
	return nil
}

// labelSet renders labels in Prometheus notation with sorted label names.
func labelSet(labels map[string]string) string {
	var b strings.Builder
	b.WriteString(labels["__name__"])
	names := slices.Sorted(maps.Keys(labels))
	names = slices.DeleteFunc(names, func(name string) bool { return name == "__name__" })
	if len(names) == 0 && b.Len() > 0 {
		return b.String()
	}
	b.WriteByte('{')
	for i, name := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(name + "=" + quoteLabelValue(labels[name]))
	}
	b.WriteByte('}')
	return b.String()
}

var labelValueEscaper = strings.NewReplacer("\\", `\\`, `"`, `\"`, "\n", `\n`)

func quoteLabelValue(s string) string { return `"` + labelValueEscaper.Replace(s) + `"` }

// flexString decodes a JSON string or number into its text.
type flexString string

func (s *flexString) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var v string
		err := json.Unmarshal(b, &v)
		*s = flexString(v)
		return err
	}
	*s = flexString(b)
	return nil
}

type point struct {
	ts    float64
	text  string
	value float64
	float bool
}

func formatSeconds(ts float64) (string, error) {
	if math.IsNaN(ts) || math.Abs(ts) > 1e11 {
		return "", errors.New("invalid sample timestamp")
	}
	return time.Unix(int64(math.Floor(ts)), 0).UTC().Format(timeLayout), nil
}

// utcTime normalizes an RFC 3339 time with any offset to UTC seconds; text
// that does not parse is returned unchanged.
func utcTime(s string) string {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return s
	}
	return t.UTC().Format(timeLayout)
}

// decodePoint reads a [timestamp, value] pair. A histogram value is an object
// of which only count and sum are kept.
func decodePoint(pair []json.RawMessage, histogram bool) (point, error) {
	var p point
	if len(pair) != 2 {
		return p, errors.New("sample must be a [timestamp, value] pair")
	}
	if err := json.Unmarshal(pair[0], &p.ts); err != nil {
		return p, errors.New("invalid sample timestamp")
	}
	if histogram {
		var h struct{ Count, Sum flexString }
		if err := json.Unmarshal(pair[1], &h); err != nil {
			return p, errors.New("invalid histogram sample")
		}
		p.text = "count=" + string(h.Count) + " sum=" + string(h.Sum)
		return p, nil
	}
	var v flexString
	if err := json.Unmarshal(pair[1], &v); err != nil {
		return p, errors.New("invalid sample value")
	}
	p.text = string(v)
	if f, err := strconv.ParseFloat(p.text, 64); err == nil {
		p.value, p.float = f, true
	}
	return p, nil
}

type sample struct {
	Metric     map[string]string   `json:"metric"`
	Value      []json.RawMessage   `json:"value"`
	Histogram  []json.RawMessage   `json:"histogram"`
	Values     [][]json.RawMessage `json:"values"`
	Histograms [][]json.RawMessage `json:"histograms"`
}

// points returns the float and histogram samples ordered by time.
func (s sample) points() ([]point, error) {
	var pts []point
	add := func(pair []json.RawMessage, histogram bool) error {
		p, err := decodePoint(pair, histogram)
		pts = append(pts, p)
		return err
	}
	if s.Value != nil {
		if err := add(s.Value, false); err != nil {
			return nil, err
		}
	}
	if s.Histogram != nil {
		if err := add(s.Histogram, true); err != nil {
			return nil, err
		}
	}
	for _, pair := range s.Values {
		if err := add(pair, false); err != nil {
			return nil, err
		}
	}
	for _, pair := range s.Histograms {
		if err := add(pair, true); err != nil {
			return nil, err
		}
	}
	slices.SortStableFunc(pts, func(a, b point) int {
		switch {
		case a.ts < b.ts:
			return -1
		case a.ts > b.ts:
			return 1
		}
		return 0
	})
	return pts, nil
}

func (f *formatter) formatQuery(data json.RawMessage, summary bool) error {
	var d struct {
		ResultType string          `json:"resultType"`
		Result     json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	if f.api == APIQueryRange && d.ResultType != "matrix" {
		return fmt.Errorf("query_range returned result type %q", d.ResultType)
	}
	switch d.ResultType {
	case "scalar", "string":
		var pair []json.RawMessage
		if err := json.Unmarshal(d.Result, &pair); err != nil {
			return err
		}
		p, err := decodePoint(pair, false)
		if err != nil {
			return err
		}
		when, err := formatSeconds(p.ts)
		if err != nil {
			return err
		}
		f.row(when, p.text)
	case "vector", "matrix":
		var samples []sample
		if err := json.Unmarshal(d.Result, &samples); err != nil {
			return err
		}
		for _, s := range samples[:f.limit(len(samples), true)] {
			pts, err := s.points()
			if err != nil {
				return err
			}
			if err := f.writeSeries(labelSet(s.Metric), pts, summary && d.ResultType == "matrix"); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported result type %q", d.ResultType)
	}
	return nil
}

func (f *formatter) writeSeries(labels string, pts []point, summary bool) error {
	if summary {
		f.summaryRow(labels, pts)
		return nil
	}
	for _, p := range pts {
		when, err := formatSeconds(p.ts)
		if err != nil {
			return err
		}
		f.row(labels, when, p.text)
	}
	return nil
}

// summaryRow writes min, avg, max and last. NaN samples do not take part in
// min, avg and max; last is the final sample as returned.
func (f *formatter) summaryRow(labels string, pts []point) {
	last := ""
	if len(pts) > 0 {
		last = pts[len(pts)-1].text
	}
	var n int
	var sum float64
	minimum, maximum := math.Inf(1), math.Inf(-1)
	floats := false
	for _, p := range pts {
		if !p.float {
			continue
		}
		floats = true
		if math.IsNaN(p.value) {
			continue
		}
		n++
		sum += p.value
		minimum, maximum = math.Min(minimum, p.value), math.Max(maximum, p.value)
	}
	switch {
	case !floats:
		f.row(labels, "", "", "", last)
	case n == 0:
		f.row(labels, "NaN", "NaN", "NaN", last)
	default:
		f.row(labels, formatFloat(minimum), formatFloat(sum/float64(n)), formatFloat(maximum), last)
	}
}

// formatFloat writes a float the way Prometheus does.
func formatFloat(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	if a := math.Abs(v); a != 0 && (a < 1e-6 || a >= 1e21) {
		return strconv.FormatFloat(v, 'e', -1, 64)
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func (f *formatter) formatAlerts(data json.RawMessage) error {
	var d struct {
		Alerts []struct {
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
			State       string            `json:"state"`
			ActiveAt    string            `json:"activeAt"`
			Value       flexString        `json:"value"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	for _, a := range d.Alerts[:f.limit(len(d.Alerts), true)] {
		f.row(a.Labels["alertname"], a.State, utcTime(a.ActiveAt), string(a.Value), labelSet(a.Labels), a.Annotations["summary"])
	}
	return nil
}

func (f *formatter) formatRules(data json.RawMessage) error {
	var d struct {
		Groups []struct {
			Name  string `json:"name"`
			Rules []struct {
				Name      string `json:"name"`
				Query     string `json:"query"`
				Type      string `json:"type"`
				Health    string `json:"health"`
				State     string `json:"state"`
				LastError string `json:"lastError"`
			} `json:"rules"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	total := 0
	for _, g := range d.Groups {
		total += len(g.Rules)
	}
	remaining := f.limit(total, true)
	for _, g := range d.Groups {
		for _, r := range g.Rules {
			if remaining == 0 {
				return nil
			}
			remaining--
			f.row(g.Name, r.Type, r.Name, r.Health, r.State, r.LastError, r.Query)
		}
	}
	return nil
}

func (f *formatter) formatTargets(data json.RawMessage) error {
	var d struct {
		ActiveTargets []struct {
			Labels     map[string]string `json:"labels"`
			ScrapePool string            `json:"scrapePool"`
			ScrapeURL  string            `json:"scrapeUrl"`
			LastError  string            `json:"lastError"`
			LastScrape string            `json:"lastScrape"`
			Health     string            `json:"health"`
		} `json:"activeTargets"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	for _, t := range d.ActiveTargets[:f.limit(len(d.ActiveTargets), true)] {
		job := t.Labels["job"]
		if job == "" {
			job = t.ScrapePool
		}
		f.row(job, t.Labels["instance"], t.Health, utcTime(t.LastScrape), t.LastError, t.ScrapeURL)
	}
	return nil
}

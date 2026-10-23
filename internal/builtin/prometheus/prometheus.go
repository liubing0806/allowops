package prometheus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/builtin/apiclient"
)

// Result is the unredacted outcome, apart from fields masked by RunRedacted.
// Stderr carries warnings, the truncation note and Prometheus error details.
type Result struct {
	Stdout     string
	Stderr     string
	ExitCode   int
	Truncated  bool
	StatusCode int
}

// request is one fixed-path GET plus the first output line.
type request struct {
	path   string
	query  url.Values
	header string
}

// Run executes one query and returns TSV output.
func Run(ctx context.Context, cfg Config, p Params) (Result, error) {
	return RunRedacted(ctx, cfg, p, nil)
}

// RunRedacted applies mask to every output cell before TSV encoding. A nil
// mask leaves the text unchanged.
func RunRedacted(ctx context.Context, cfg Config, p Params, mask func(string) string) (Result, error) {
	failed := Result{ExitCode: builtin.ExitFailure}
	cfg, err := cfg.resolve()
	if err != nil {
		return failed, err
	}
	req, err := cfg.buildRequest(p, now())
	if err != nil {
		return failed, err
	}
	client, err := apiclient.New(cfg.Config)
	if err != nil {
		return failed, err
	}
	defer client.Close()
	resp, err := client.Get(ctx, req.path, req.query)
	if err != nil {
		return failed, err
	}
	result := Result{ExitCode: builtin.ExitFailure, StatusCode: resp.StatusCode}
	var env envelope
	jsonErr := json.Unmarshal(resp.Body, &env)
	if jsonErr == nil {
		for _, w := range env.Warnings {
			result.Stderr += "warning: " + singleLine(w) + "\n"
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 || jsonErr != nil || env.Status != "success" {
		result.Stderr += failureLine(resp.StatusCode, env, jsonErr)
		return result, nil
	}
	f := formatter{api: cfg.API, label: p.Label, maxSeries: cfg.MaxSeries, mask: mask}
	f.header(req.header)
	if err := f.format(env.Data, p.Summary); err != nil {
		result.Stderr = ""
		return failed, fmt.Errorf("unexpected Prometheus response: %w", err)
	}
	result.Stdout, result.ExitCode, result.Truncated = f.out.String(), builtin.ExitSuccess, f.truncated
	result.Stderr += f.note
	return result, nil
}

type envelope struct {
	Status    string          `json:"status"`
	Data      json.RawMessage `json:"data"`
	ErrorType string          `json:"errorType"`
	Error     string          `json:"error"`
	Warnings  []string        `json:"warnings"`
}

func failureLine(status int, env envelope, jsonErr error) string {
	switch {
	case jsonErr != nil:
		return fmt.Sprintf("error: HTTP %d with a non-JSON response body\n", status)
	case env.ErrorType != "" || env.Error != "":
		return fmt.Sprintf("error: HTTP %d errorType=%s error=%s\n", status, singleLine(env.ErrorType), singleLine(env.Error))
	}
	return fmt.Sprintf("error: HTTP %d with status %q\n", status, singleLine(env.Status))
}

// singleLine keeps one message on one stderr line.
func singleLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s)
}

// timeoutParam formats the client timeout the way Prometheus reads it: seconds.
func timeoutParam(d time.Duration) string { return strconv.FormatFloat(d.Seconds(), 'f', -1, 64) }

func requestTime(t time.Time) string { return t.UTC().Format(timeLayout) }

// buildRequest checks the cross-parameter limits and renders the request.
func (c Config) buildRequest(p Params, at time.Time) (request, error) {
	q := url.Values{}
	switch c.API {
	case APIQuery:
		if p.Query == "" {
			return request{}, errors.New("query is required")
		}
		t, err := parseOptionalTime("time", p.Time, "now", at)
		if err != nil {
			return request{}, err
		}
		q.Set("query", p.Query)
		q.Set("time", requestTime(t))
		q.Set("timeout", timeoutParam(c.Timeout))
		return request{path: "/api/v1/query", query: q, header: "api=query time=" + requestTime(t)}, nil
	case APIQueryRange:
		if p.Query == "" {
			return request{}, errors.New("query is required")
		}
		if p.Start == "" {
			return request{}, errors.New("start is required")
		}
		start, end, err := c.timeRange(p, at)
		if err != nil {
			return request{}, err
		}
		step, err := c.queryStep(p.Step, p.HasStep, start, end)
		if err != nil {
			return request{}, err
		}
		q.Set("query", p.Query)
		q.Set("start", requestTime(start))
		q.Set("end", requestTime(end))
		q.Set("step", strconv.FormatFloat(step.Seconds(), 'f', -1, 64))
		q.Set("timeout", timeoutParam(c.Timeout))
		header := fmt.Sprintf("api=query_range start=%s end=%s step=%ss", requestTime(start), requestTime(end), strconv.FormatFloat(step.Seconds(), 'f', -1, 64))
		return request{path: "/api/v1/query_range", query: q, header: header}, nil
	case APISeries, APILabels, APILabelValues:
		if len(p.Match) == 0 && c.API == APISeries {
			return request{}, errors.New("match is required")
		}
		path := "/api/v1/" + c.API
		if c.API == APILabelValues {
			if len(p.Label) > 128 || !labelName.MatchString(p.Label) {
				return request{}, errors.New("label must match " + labelPattern)
			}
			path = "/api/v1/label/" + p.Label + "/values"
		}
		start, end, err := c.timeRange(p, at)
		if err != nil {
			return request{}, err
		}
		q.Set("start", requestTime(start))
		q.Set("end", requestTime(end))
		if len(p.Match) > 0 {
			q["match[]"] = append([]string(nil), p.Match...)
		}
		q.Set("limit", strconv.Itoa(c.MaxSeries+1))
		return request{path: path, query: q, header: fmt.Sprintf("api=%s start=%s end=%s", c.API, requestTime(start), requestTime(end))}, nil
	case APIRules:
		switch p.RuleType {
		case "":
		case "alert", "record":
			q.Set("type", p.RuleType)
		default:
			return request{}, errors.New("rule_type must be alert or record")
		}
		q.Set("exclude_alerts", "true")
		return request{path: "/api/v1/rules", query: q, header: "api=rules"}, nil
	case APITargets:
		q.Set("state", "active")
		return request{path: "/api/v1/targets", query: q, header: "api=targets"}, nil
	case APIAlerts:
		return request{path: "/api/v1/alerts", query: q, header: "api=alerts"}, nil
	}
	return request{}, fmt.Errorf("unsupported prometheus api %q", c.API)
}

func parseOptionalTime(name, value, def string, at time.Time) (time.Time, error) {
	if value == "" {
		value = def
	}
	t, err := ParseTime(value, at)
	if err != nil {
		return t, fmt.Errorf("%s: %w", name, err)
	}
	return t, nil
}

// timeRange resolves start and end and enforces start < end and max_range. An
// omitted start is one hour before end, or max_range if that is shorter.
func (c Config) timeRange(p Params, at time.Time) (start, end time.Time, err error) {
	if end, err = parseOptionalTime("end", p.End, "now", at); err != nil {
		return
	}
	if p.Start == "" {
		start = end.Add(-min(time.Hour, c.MaxRange))
	} else if start, err = parseOptionalTime("start", p.Start, "", at); err != nil {
		return
	}
	if !start.Before(end) {
		err = errors.New("start must be before end")
	} else if end.Sub(start) > c.MaxRange {
		err = fmt.Errorf("end - start exceeds max_range %s", c.MaxRange)
	}
	return
}

// queryStep returns the requested step or derives one from max_points, and
// checks the number of points per series.
func (c Config) queryStep(requested time.Duration, given bool, start, end time.Time) (time.Duration, error) {
	span := end.Sub(start)
	step := requested
	if !given {
		// Times are whole seconds, so the span is too.
		intervals := int64(c.MaxPoints - 1)
		seconds := (int64(span/time.Second) + intervals - 1) / intervals
		step = max(time.Duration(seconds)*time.Second, c.MinStep)
	} else if step < c.MinStep {
		return 0, fmt.Errorf("step must be at least min_step %s", c.MinStep)
	}
	if points := int64(span/step) + 1; points > int64(c.MaxPoints) {
		return 0, fmt.Errorf("query would return %d points per series, above max_points %d", points, c.MaxPoints)
	}
	return step, nil
}

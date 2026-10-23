// Package alertmanager implements the read-only alertmanager_alerts builtin.
// It only issues GET /api/v2/alerts through the shared API client.
package alertmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/liubing0806/allowops/internal/builtin/apiclient"
)

// Limits. Configuration may only tighten them; zero selects the default.
const (
	DefaultTimeout                = 10 * time.Second
	MaxTimeout                    = 30 * time.Second
	DefaultMaxAlerts              = 100
	MaxAlerts                     = 1000
	DefaultMaxResponseBytes int64 = 4 << 20
	MaxResponseBytes        int64 = 16 << 20

	alertsPath    = "/api/v2/alerts"
	maxErrorBytes = 512
)

// Config is trusted catalog configuration.
type Config struct {
	Address          string
	Credential       string
	CAFile           string
	Timeout          time.Duration
	MaxAlerts        int
	MaxResponseBytes int64
}

// Params are the caller-supplied query options. A false value excludes the
// corresponding alert state; the catalog adapter supplies the defaults.
type Params struct {
	Filter                      []string
	Active, Silenced, Inhibited bool
}

// Result is raw handler output. Truncated reports a max_alerts cut.
type Result struct {
	Stdout, Stderr string
	ExitCode       int
	Truncated      bool
}

// effective returns the configuration with defaults applied, or the first
// limit violation.
func (c Config) effective() (Config, error) {
	var err error
	if c.Timeout, err = apiclient.Tighten("timeout", c.Timeout, DefaultTimeout, MaxTimeout); err != nil {
		return c, err
	}
	if c.MaxAlerts, err = apiclient.Tighten("max_alerts", c.MaxAlerts, DefaultMaxAlerts, MaxAlerts); err != nil {
		return c, err
	}
	if c.MaxResponseBytes, err = apiclient.Tighten("max_response_bytes", c.MaxResponseBytes, DefaultMaxResponseBytes, MaxResponseBytes); err != nil {
		return c, err
	}
	return c, nil
}

func (c Config) client() apiclient.Config {
	return apiclient.Config{Address: c.Address, Credential: c.Credential, CAFile: c.CAFile, Timeout: c.Timeout, MaxResponseBytes: c.MaxResponseBytes}
}

// Validate checks limits, the address and the file paths without touching the
// file system.
func (c Config) Validate() error {
	c, err := c.effective()
	if err != nil {
		return err
	}
	return c.client().Validate()
}

// UsesCredential reports whether the action reads a credential file.
func (c Config) UsesCredential() bool { return c.Credential != "" }

type alert struct {
	StartsAt     string            `json:"startsAt"`
	Fingerprint  string            `json:"fingerprint"`
	GeneratorURL string            `json:"generatorURL"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	Status       struct {
		State       string   `json:"state"`
		SilencedBy  []string `json:"silencedBy"`
		InhibitedBy []string `json:"inhibitedBy"`
	} `json:"status"`
	started time.Time
}

// Run queries Alertmanager and renders the alerts as TSV. mask redacts original
// field text before TSV escaping; nil leaves text unchanged. An HTTP error
// status is reported through Result (exit code 1 and stderr); transport and
// decoding failures are returned as errors.
func Run(ctx context.Context, cfg Config, p Params, mask func(string) string) (Result, error) {
	failed := Result{ExitCode: 1}
	cfg, err := cfg.effective()
	if err != nil {
		return failed, err
	}
	client, err := apiclient.New(cfg.client())
	if err != nil {
		return failed, err
	}
	defer client.Close()
	query := url.Values{
		"active":    {fmt.Sprint(p.Active)},
		"silenced":  {fmt.Sprint(p.Silenced)},
		"inhibited": {fmt.Sprint(p.Inhibited)},
	}
	if len(p.Filter) > 0 {
		query["filter"] = p.Filter
	}
	resp, err := client.Get(ctx, alertsPath, query)
	switch {
	case errors.Is(err, apiclient.ErrRedirect):
		return failed, fmt.Errorf("alertmanager answered with a redirect, which is never followed: %w", err)
	case errors.Is(err, apiclient.ErrResponseTooLarge):
		return failed, fmt.Errorf("alertmanager response exceeds max_response_bytes (%d): %w", cfg.MaxResponseBytes, err)
	case err != nil:
		return failed, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		failed.Stderr = fmt.Sprintf("alertmanager returned HTTP %d %s: %s\n", resp.StatusCode, http.StatusText(resp.StatusCode), oneLine(resp.Body, maxErrorBytes))
		return failed, nil
	}
	var alerts []*alert
	if err := json.Unmarshal(resp.Body, &alerts); err != nil {
		return failed, errors.New("invalid alertmanager response: expected a JSON array of alerts")
	}
	alerts = slicesNonNil(alerts)
	for _, a := range alerts {
		a.started, _ = time.Parse(time.RFC3339Nano, a.StartsAt)
	}
	sort.SliceStable(alerts, func(i, j int) bool {
		if !alerts[i].started.Equal(alerts[j].started) {
			return alerts[i].started.Before(alerts[j].started)
		}
		return alerts[i].Fingerprint < alerts[j].Fingerprint
	})
	result := Result{}
	if total := len(alerts); total > cfg.MaxAlerts {
		alerts = alerts[:cfg.MaxAlerts]
		result.Truncated = true
		result.Stderr = fmt.Sprintf("truncated: returned %d of %d alerts (max_alerts=%d)\n", len(alerts), total, cfg.MaxAlerts)
	}
	if mask == nil {
		mask = func(s string) string { return s }
	}
	var out strings.Builder
	for _, a := range alerts {
		writeAlert(&out, a, mask)
	}
	result.Stdout = out.String()
	return result, nil
}

// slicesNonNil drops null array elements.
func slicesNonNil(alerts []*alert) []*alert {
	kept := alerts[:0]
	for _, a := range alerts {
		if a != nil {
			kept = append(kept, a)
		}
	}
	return kept
}

// labelsField is the index of the label set in a row.
const labelsField = 4

func writeAlert(out *strings.Builder, a *alert, mask func(string) string) {
	startsAt := a.StartsAt
	if !a.started.IsZero() {
		startsAt = a.started.UTC().Format(time.RFC3339)
	}
	rest := make(map[string]string, len(a.Labels))
	for name, value := range a.Labels {
		if name != "alertname" && name != "severity" {
			rest[name] = value
		}
	}
	fields := []string{
		startsAt,
		a.Status.State,
		a.Labels["alertname"],
		a.Labels["severity"],
		labelSet(rest, mask),
		a.Annotations["summary"],
		a.Annotations["description"],
		strings.Join(a.Status.SilencedBy, ","),
		strings.Join(a.Status.InhibitedBy, ","),
		expr(a.GeneratorURL),
	}
	for i, field := range fields {
		if i > 0 {
			out.WriteByte('\t')
		}
		if i != labelsField {
			field = mask(field) // The label set is masked label by label.
		}
		out.WriteString(escapeTSV(field))
	}
	out.WriteByte('\n')
}

// labelSet writes labels in Prometheus notation with names in byte order. Each
// name="value" pair is masked on its own: a rule that matches to the end of the
// line would otherwise swallow the labels after the one it redacts.
func labelSet(labels map[string]string, mask func(string) string) string {
	names := make([]string, 0, len(labels))
	for name := range labels {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteByte('{')
	for i, name := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		pair := name
		if !validLabelName(name) {
			pair = quote(name)
		}
		b.WriteString(mask(pair + "=" + quote(labels[name])))
	}
	b.WriteByte('}')
	return b.String()
}

func validLabelName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

var labelValueEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)

func quote(s string) string { return `"` + labelValueEscaper.Replace(s) + `"` }

// expr returns the PromQL expression Prometheus embeds in generatorURL as the
// g0.expr query parameter. Anything unparsable yields an empty string. Other
// parameters are not decoded, so an encoding error elsewhere in the query does
// not discard a valid expression.
func expr(generatorURL string) string {
	if generatorURL == "" {
		return ""
	}
	u, err := url.Parse(generatorURL)
	if err != nil {
		return ""
	}
	for _, pair := range strings.Split(u.RawQuery, "&") {
		if value, ok := strings.CutPrefix(pair, "g0.expr="); ok {
			decoded, err := url.QueryUnescape(value)
			if err != nil {
				return ""
			}
			return decoded
		}
	}
	return ""
}

var tsvEscaper = strings.NewReplacer("\\", "\\\\", "\t", `\t`, "\n", `\n`, "\r", `\r`, "\x00", `\0`)

func escapeTSV(s string) string { return tsvEscaper.Replace(s) }

// oneLine renders an error body for stderr: control characters become spaces
// and the text is cut at limit bytes on a rune boundary.
func oneLine(body []byte, limit int) string {
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(string(body), "?") {
		if r < ' ' || r == 0x7f {
			r = ' '
		}
		if b.Len()+len(string(r)) > limit {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// Package starrocksprofile parses the text of a merged StarRocks query profile
// (the result of get_query_profile) and derives the summary and rule findings
// that starrocks_diag returns for the profile_summary and profile_run
// operations.
//
// The parser reads only the metrics it needs. It is written against StarRocks
// 3.3 profiles; a metric that is absent or has an unknown format is treated as
// not reported, never as zero evidence of a problem.
package starrocksprofile

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// MaxLines bounds the number of profile lines that Parse accepts.
const MaxLines = 400000

// Metric is one counter line. Max and Min come from the __MAX_OF_ and
// __MIN_OF_ children that the merge adds when a fragment has several instances.
type Metric struct {
	Raw    string
	Max    string
	Min    string
	hasMax bool
}

// Operator is one operator section of one pipeline.
type Operator struct {
	Fragment   int
	Pipeline   int
	Name       string
	PlanNodeID int
	// NodeType is the plan node name from the topology, such as "AGGREGATION".
	NodeType string
	metrics  map[string]*Metric
}

// Profile is a parsed query profile.
type Profile struct {
	Summary   map[string]string
	Execution map[string]string
	// SessionVariables holds the actual value of every non-default session variable.
	SessionVariables map[string]string
	Operators        []*Operator
	// QueryMemoryLimit is the largest positive QueryMemoryLimit of a fragment.
	QueryMemoryLimit int64
	// MemLimitExceeded is set when an ErrorMsg metric reports a memory limit error.
	MemLimitExceeded bool
}

type node struct {
	indent   int
	text     string
	children []*node
}

// memLimitMessage matches the backend's memory limit errors, for example
// "Memory of Query<id> exceed limit. ... Mem usage has exceed the limit of single query".
var memLimitMessage = regexp.MustCompile(`(?i)exceed(ed)? (the )?limit|MEM_LIMIT_EXCEEDED`)

var errNoProfile = errors.New("the profile text is empty or has no Summary section")

// Parse parses the text of a merged profile.
func Parse(text string) (*Profile, error) {
	root := &node{indent: -1}
	stack := []*node{root}
	lines := 0
	memLimitExceeded := false
	for _, raw := range strings.Split(text, "\n") {
		raw = strings.TrimRight(raw, "\r \t")
		trimmed := strings.TrimLeft(raw, " ")
		if trimmed == "" {
			continue
		}
		if lines++; lines > MaxLines {
			return nil, fmt.Errorf("the profile has more than %d lines", MaxLines)
		}
		n := &node{indent: len(raw) - len(trimmed), text: trimmed}
		if strings.HasPrefix(trimmed, "- ErrorMsg") && memLimitMessage.MatchString(trimmed) {
			memLimitExceeded = true
		}
		for len(stack) > 1 && stack[len(stack)-1].indent >= n.indent {
			stack = stack[:len(stack)-1]
		}
		parent := stack[len(stack)-1]
		parent.children = append(parent.children, n)
		stack = append(stack, n)
	}
	query := find(root, "Query:")
	if query == nil {
		return nil, errNoProfile
	}
	p := &Profile{Summary: map[string]string{}, Execution: map[string]string{}, SessionVariables: map[string]string{}, MemLimitExceeded: memLimitExceeded}
	summary := find(query, "Summary:")
	if summary == nil {
		return nil, errNoProfile
	}
	for _, c := range summary.children {
		if k, v, ok := splitMetric(c.text); ok {
			p.Summary[k] = v
		}
	}
	p.parseVariables()
	execution := find(query, "Execution:")
	if execution == nil {
		return p, nil
	}
	for _, c := range execution.children {
		if k, v, ok := splitMetric(c.text); ok {
			p.Execution[k] = v
		}
	}
	topology := parseTopology(p.Execution["Topology"])
	delete(p.Execution, "Topology")
	for _, f := range execution.children {
		id, ok := headerNumber(f.text, "Fragment ")
		if !ok {
			continue
		}
		for _, m := range f.children {
			if k, v, ok := splitMetric(m.text); ok && k == "QueryMemoryLimit" {
				if b, ok := ParseBytes(v); ok && b > p.QueryMemoryLimit {
					p.QueryMemoryLimit = b
				}
			}
		}
		for _, pl := range f.children {
			pipeline, ok := headerNumber(pl.text, "Pipeline (id=")
			if !ok {
				continue
			}
			for _, o := range pl.children {
				name, planID, ok := operatorHeader(o.text)
				if !ok {
					continue
				}
				op := &Operator{Fragment: id, Pipeline: pipeline, Name: name, PlanNodeID: planID, NodeType: topology[planID], metrics: map[string]*Metric{}}
				for _, section := range o.children {
					collect(op.metrics, section)
				}
				p.Operators = append(p.Operators, op)
			}
		}
	}
	return p, nil
}

func (p *Profile) parseVariables() {
	var vars map[string]struct {
		Actual json.RawMessage `json:"actualValue"`
	}
	if json.Unmarshal([]byte(p.Summary["NonDefaultSessionVariables"]), &vars) != nil {
		return
	}
	for name, v := range vars {
		p.SessionVariables[name] = strings.Trim(string(v.Actual), `"`)
	}
}

func find(n *node, text string) *node {
	for _, c := range n.children {
		if c.text == text {
			return c
		}
	}
	return nil
}

// splitMetric splits "- Name: value" into name and value. A line without a
// value, such as "- IsFinalSink", returns an empty value.
func splitMetric(text string) (name, value string, ok bool) {
	rest, found := strings.CutPrefix(text, "- ")
	if !found || strings.HasPrefix(rest, "-") {
		return "", "", false
	}
	name, value, _ = strings.Cut(rest, ": ")
	return strings.TrimSpace(name), strings.TrimSpace(value), true
}

func headerNumber(text, prefix string) (int, bool) {
	rest, ok := strings.CutPrefix(text, prefix)
	if !ok {
		return 0, false
	}
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	n, err := strconv.Atoi(rest[:end])
	return n, err == nil && end > 0
}

var operatorPattern = regexp.MustCompile(`^([A-Z][A-Z0-9_]*) \(plan_node_id=(-?\d+)\):$`)

func operatorHeader(text string) (string, int, bool) {
	m := operatorPattern.FindStringSubmatch(text)
	if m == nil {
		return "", 0, false
	}
	id, err := strconv.Atoi(m[2])
	return m[1], id, err == nil
}

// collect adds every metric below section to metrics. The first occurrence of
// a name wins, which keeps the top-level counter when a nested one has the same name.
func collect(metrics map[string]*Metric, section *node) {
	var walk func(n *node)
	walk = func(n *node) {
		for _, c := range n.children {
			name, value, ok := splitMetric(c.text)
			if !ok {
				continue
			}
			switch {
			case strings.HasPrefix(name, "__MAX_OF_"):
				if m := metrics[strings.TrimPrefix(name, "__MAX_OF_")]; m != nil && !m.hasMax {
					m.Max, m.hasMax = value, true
				}
				continue
			case strings.HasPrefix(name, "__MIN_OF_"):
				if m := metrics[strings.TrimPrefix(name, "__MIN_OF_")]; m != nil && m.Min == "" {
					m.Min = value
				}
				continue
			}
			if _, exists := metrics[name]; !exists {
				metrics[name] = &Metric{Raw: value}
			}
			walk(c)
		}
	}
	walk(section)
}

type topologyNode struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func parseTopology(text string) map[int]string {
	var t struct {
		Nodes []topologyNode `json:"nodes"`
	}
	result := map[int]string{}
	if json.Unmarshal([]byte(text), &t) == nil {
		for _, n := range t.Nodes {
			result[n.ID] = n.Name
		}
	}
	return result
}

var durationPart = regexp.MustCompile(`^(\d+(?:\.\d+)?)(ms|us|ns|h|m|s)`)

// ParseDuration parses the profile duration format: "17ms", "1.119us", "0ns",
// "1s234ms", "1m2s", "1h2m3s".
func ParseDuration(s string) (time.Duration, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, s == "0"
	}
	var total float64
	for s != "" {
		m := durationPart.FindStringSubmatch(s)
		if m == nil {
			return 0, false
		}
		v, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return 0, false
		}
		unit := map[string]float64{"h": 3.6e12, "m": 6e10, "s": 1e9, "ms": 1e6, "us": 1e3, "ns": 1}[m[2]]
		total += v * unit
		s = s[len(m[0]):]
	}
	if total > math.MaxInt64 {
		return 0, false
	}
	return time.Duration(total), true
}

var bytesPattern = regexp.MustCompile(`^(\d+(?:\.\d+)?) (B|KB|MB|GB|TB|PB)$`)

// ParseBytes parses "11.424 MB" with binary multiples.
func ParseBytes(s string) (int64, bool) {
	m := bytesPattern.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	shift := map[string]int{"B": 0, "KB": 10, "MB": 20, "GB": 30, "TB": 40, "PB": 50}[m[2]]
	total := v * float64(int64(1)<<shift)
	if total > math.MaxInt64 {
		return 0, false
	}
	return int64(total), true
}

var countPattern = regexp.MustCompile(`^(-?\d+(?:\.\d+)?)([KMB]?)(?: \((-?\d+)\))?$`)

// ParseCount parses "50", "500.000K (500000)" and "1.5M". The exact value in
// parentheses wins over the rounded prefix form.
func ParseCount(s string) (int64, bool) {
	m := countPattern.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, false
	}
	if m[3] != "" {
		n, err := strconv.ParseInt(m[3], 10, 64)
		return n, err == nil
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	v *= map[string]float64{"": 1, "K": 1e3, "M": 1e6, "B": 1e9}[m[2]]
	if v > math.MaxInt64 {
		return 0, false
	}
	return int64(v), true
}

// Duration returns a time metric.
func (o *Operator) Duration(name string) (time.Duration, bool) {
	if m := o.metrics[name]; m != nil {
		return ParseDuration(m.Raw)
	}
	return 0, false
}

// MaxDuration returns the largest per-instance value of a time metric.
func (o *Operator) MaxDuration(name string) (time.Duration, bool) {
	if m := o.metrics[name]; m != nil && m.hasMax {
		return ParseDuration(m.Max)
	}
	return 0, false
}

// Bytes returns a size metric.
func (o *Operator) Bytes(name string) (int64, bool) {
	if m := o.metrics[name]; m != nil {
		return ParseBytes(m.Raw)
	}
	return 0, false
}

// Count returns a row or event counter.
func (o *Operator) Count(name string) (int64, bool) {
	if m := o.metrics[name]; m != nil {
		return ParseCount(m.Raw)
	}
	return 0, false
}

// SpillBytes returns the sum of the operator's byte counters whose name
// contains "Spill". StarRocks 3.3 reports spill counters only on operators
// that spilled, so a missing counter means no spill.
func (o *Operator) SpillBytes() int64 {
	var total int64
	for name, m := range o.metrics {
		if strings.Contains(name, "Spill") {
			if b, ok := ParseBytes(m.Raw); ok {
				total += b
			}
		}
	}
	return total
}

package logquery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/liubing0806/allowops/internal/params"
)

const (
	DefaultPatternsTop = 20
	MaxPatternsTop     = 100
	// maxClusters bounds memory; records that would start a new cluster
	// beyond it are counted as unclustered.
	maxClusters = 2000
	// patternInput is the part of a record's first line that is clustered
	// and kept as the sample before redaction.
	patternInput = 4096
	// patternText bounds the template and sample after redaction.
	patternText = 1024
	// Drain parameters: prefix tokens used as tree levels below the token
	// count, the similarity needed to join a cluster, and children per node.
	drainPrefix     = 2
	drainSimilarity = 0.4
	drainChildren   = 100
	variable        = "<_>"
	wildcardKey     = "<*>"
)

// variablePatterns replace variable parts of a line before clustering, in
// order: timestamps, UUIDs, IP addresses with optional port, hexadecimal
// numbers and decimal numbers.
var variablePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?|\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}|\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}(?: [+-]\d{4})?|\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?`),
	regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`),
	regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b`),
	regexp.MustCompile(`\b0[xX][0-9a-fA-F]+\b`),
}

var (
	hexWord = regexp.MustCompile(`\b[0-9a-fA-F]{8,}\b`)
	number  = regexp.MustCompile(`\b\d+(?:\.\d+)?\b`)
)

// maskVariables replaces the variable parts of line with <_>.
func maskVariables(line string) string {
	for _, re := range variablePatterns {
		line = re.ReplaceAllLiteralString(line, variable)
	}
	line = hexWord.ReplaceAllStringFunc(line, func(word string) string {
		if strings.ContainsAny(word, "0123456789") {
			return variable
		}
		return word
	})
	return number.ReplaceAllLiteralString(line, variable)
}

// PatternsOutput is the patterns mode result (design 7.2).
type PatternsOutput struct {
	Source   string    `json:"source"`
	Since    string    `json:"since"`
	Until    string    `json:"until"`
	Patterns []Pattern `json:"patterns"`
	// Records is the number of records clustered, Clusters the number of
	// templates found, of which Patterns holds the top ones.
	Records     int `json:"records"`
	Clusters    int `json:"clusters"`
	Unclustered int `json:"unclustered,omitempty"`
	// Omitted counts top templates left out to fit max_output.
	Omitted          int        `json:"omitted,omitempty"`
	Files            FileCounts `json:"files"`
	ScannedBytes     int64      `json:"scanned_bytes"`
	ScanLimitReached bool       `json:"scan_limit_reached"`
	ScannedUntil     string     `json:"scanned_until"`
}

// Pattern is one template; Template and Sample are redacted.
type Pattern struct {
	Template string `json:"template"`
	Count    int    `json:"count"`
	First    string `json:"first"`
	Last     string `json:"last"`
	Sample   string `json:"sample"`
}

func patternsParameters(cfg Config) map[string]params.Definition {
	cfg.Mode = ModeSearch
	search := Parameters(cfg)
	defs := map[string]params.Definition{}
	for _, name := range []string{"source", "since", "until", "exclude", "level"} {
		if def, ok := search[name]; ok {
			defs[name] = def
		}
	}
	one := int64(1)
	defs["top"] = params.Definition{Type: params.Int, Description: "Number of templates returned, most frequent first", Min: &one, Max: MaxPatternsTop, Default: DefaultPatternsTop}
	return defs
}

type cluster struct {
	tokens      []string
	count       int
	first, last time.Time
	sample      string
	order       int
}

type drainNode struct {
	children map[string]*drainNode
	clusters []*cluster
}

// drain clusters lines with the Drain algorithm: lines are grouped by token
// count and their first drainPrefix tokens, then joined to the most similar
// cluster of the group. Input order fully determines the result.
type drain struct {
	byLength    map[int]*drainNode
	clusters    []*cluster
	unclustered int
}

func hasVariable(token string) bool {
	return strings.Contains(token, variable) || strings.ContainsAny(token, "0123456789")
}

func (d *drain) leaf(tokens []string) *drainNode {
	node := d.byLength[len(tokens)]
	if node == nil {
		node = &drainNode{children: map[string]*drainNode{}}
		d.byLength[len(tokens)] = node
	}
	for _, token := range tokens[:min(drainPrefix, len(tokens))] {
		key := token
		if hasVariable(token) {
			key = wildcardKey
		}
		child := node.children[key]
		if child == nil && len(node.children) >= drainChildren {
			key = wildcardKey
			child = node.children[key]
		}
		if child == nil {
			child = &drainNode{children: map[string]*drainNode{}}
			node.children[key] = child
		}
		node = child
	}
	return node
}

func similarity(template, tokens []string) float64 {
	if len(tokens) == 0 {
		return 1
	}
	same := 0
	for i, token := range template {
		if token != variable && token == tokens[i] {
			same++
		}
	}
	return float64(same) / float64(len(tokens))
}

func (d *drain) add(line string, at time.Time) {
	line = cut(line, patternInput)
	tokens := strings.Fields(maskVariables(line))
	node := d.leaf(tokens)
	var best *cluster
	bestSimilarity := -1.0
	for _, c := range node.clusters {
		if sim := similarity(c.tokens, tokens); sim > bestSimilarity {
			best, bestSimilarity = c, sim
		}
	}
	if best == nil || bestSimilarity < drainSimilarity {
		if len(d.clusters) == maxClusters {
			d.unclustered++
			return
		}
		best = &cluster{tokens: tokens, first: at, last: at, sample: line, order: len(d.clusters)}
		node.clusters = append(node.clusters, best)
		d.clusters = append(d.clusters, best)
	} else {
		for i, token := range best.tokens {
			if token != tokens[i] {
				best.tokens[i] = variable
			}
		}
		if at.Before(best.first) {
			best.first = at
		}
		best.last = maxTime(best.last, at)
	}
	best.count++
}

// top returns the n most frequent clusters; ties go to the earlier first
// occurrence, then the earlier cluster.
func (d *drain) top(n int) []*cluster {
	sorted := slices.Clone(d.clusters)
	slices.SortStableFunc(sorted, func(a, b *cluster) int {
		if a.count != b.count {
			return b.count - a.count
		}
		if c := a.first.Compare(b.first); c != 0 {
			return c
		}
		return a.order - b.order
	})
	return sorted[:min(n, len(sorted))]
}

func firstLine(text string) string {
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		return text[:i]
	}
	return text
}

func runPatterns(ctx context.Context, cfg Config, roots []string, p Params, redact func(string) string, maxOutput int64) ([]byte, bool, error) {
	if p.Pattern != "" || p.Fixed || p.IgnoreCase {
		return nil, false, errors.New("patterns mode accepts no pattern, fixed or ignore_case")
	}
	if p.Top == 0 {
		p.Top = DefaultPatternsTop
	}
	if p.Top < 1 || p.Top > MaxPatternsTop {
		return nil, false, fmt.Errorf("top allowed 1..%d", MaxPatternsTop)
	}
	q, err := prepareScan(ctx, cfg, roots, p)
	if err != nil {
		return nil, false, err
	}
	defer q.close()
	s := q.s
	d := &drain{byLength: map[int]*drainNode{}}
	records := 0
	err = q.walk(ctx, func(_ string, r record) {
		if s.match(r.text) {
			records++
			d.add(firstLine(r.text), r.time)
		}
	})
	if err != nil {
		return nil, false, err
	}
	location := s.parser.location
	out := PatternsOutput{Source: p.Source, Since: formatTime(s.since, location), Until: formatTime(s.until, location), Records: records, Clusters: len(d.clusters),
		Unclustered: d.unclustered, Files: q.fileCounts(), ScannedBytes: s.scanned, ScanLimitReached: s.limited, ScannedUntil: formatTime(s.scannedUntil(), location)}
	top := d.top(p.Top)
	patterns := make([]Pattern, len(top))
	for i, c := range top {
		// Redact before shortening, so a cut cannot split a secret the
		// redaction rules would recognize.
		patterns[i] = Pattern{Template: cut(redact(strings.Join(c.tokens, " ")), patternText), Count: c.count,
			First: formatTime(c.first, location), Last: formatTime(c.last, location), Sample: cut(redact(c.sample), patternText)}
	}
	encode := func(n int) ([]byte, error) {
		page := out
		page.Patterns, page.Omitted = patterns[:n], len(patterns)-n
		data, err := json.Marshal(page)
		return append(data, '\n'), err
	}
	data, err := encode(len(patterns))
	if err != nil || maxOutput <= 0 || int64(len(data)) <= maxOutput {
		return data, s.limited, err
	}
	// Largest n whose encoding fits; encode(0) is assumed to fit.
	lo, hi := 0, len(patterns)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if data, err = encode(mid); err != nil {
			return nil, false, err
		}
		if int64(len(data)) <= maxOutput {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	data, err = encode(lo)
	return data, s.limited, err
}

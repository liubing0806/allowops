package executor

import (
	"bytes"
	"fmt"
	"github.com/liubing0806/allowops/internal/params"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

type FilterOptions struct {
	Match, Exclude string
	Tail, Head     int64
	Count          bool
	excludeSet     bool
	countSet       bool
}

// A17: match/exclude may combine with at most one result filter.
func validateFilterCombination(options FilterOptions) error {
	selected := 0
	if options.Tail > 0 {
		selected++
	}
	if options.Head > 0 {
		selected++
	}
	if options.countSet {
		selected++
	}
	if selected > 1 {
		return fmt.Errorf("tail, head and count are mutually exclusive; allowed: match/exclude, optionally with one of tail, head, count")
	}
	return nil
}

func ParseFilters(allowed []string, input map[string]any) (FilterOptions, error) {
	var out FilterOptions
	for name, value := range input {
		if !slices.Contains(allowed, name) {
			return out, fmt.Errorf("filter %s is not allowed", name)
		}
		switch name {
		case "match", "exclude":
			pattern, ok := value.(string)
			if !ok || !utf8.ValidString(pattern) || utf8.RuneCountInString(pattern) > 200 || strings.ContainsAny(pattern, "\x00\r\n") {
				return out, fmt.Errorf("filter %s requires RE2 string of at most 200 characters", name)
			}
			if _, err := regexp.Compile(pattern); err != nil {
				return out, fmt.Errorf("filter %s: %w", name, err)
			}
			if name == "match" {
				out.Match = pattern
			} else {
				out.Exclude = pattern
				out.excludeSet = true
			}
		case "tail", "head":
			// The shared int parser rejects fractional and overflowing JSON numbers.
			n, err := parseLineCount(value)
			if err != nil {
				return out, fmt.Errorf("filter %s: %w", name, err)
			}
			if name == "tail" {
				out.Tail = n
			} else {
				out.Head = n
			}
		case "count":
			b, ok := value.(bool)
			if !ok {
				return out, fmt.Errorf("filter count requires boolean")
			}
			out.Count = b
			out.countSet = true
		default:
			return out, fmt.Errorf("unknown filter %s", name)
		}
	}
	return out, validateFilterCombination(out)
}

func parseLineCount(value any) (int64, error) {
	min := int64(1)
	values, err := params.Parse(map[string]params.Definition{"lines": {Type: params.Int, Description: "Line count", Min: &min}}, map[string]any{"lines": value})
	if err != nil {
		return 0, err
	}
	return values["lines"].(int64), nil
}

// filterWriter applies match/exclude/head/count/tail to a stream of redacted
// lines, one line per Write. tail retains the newest lines in one contiguous
// buffer instead of a slice of strings: retained bytes stay within the output
// limit plus the newest line, whatever tail asks for, so a huge tail over a
// huge stream cannot exhaust memory. Older lines are evicted first; losing a
// line that tail asked for sets the output's truncated flag.
type filterWriter struct {
	output         *limitedOutput
	options        FilterOptions
	match, exclude *regexp.Regexp
	// tailData[tailStart:] holds the retained lines. Only the final line of a
	// stream may lack its "\n", so line boundaries are found by scanning
	// instead of keeping a per-line index that would dominate memory for
	// streams of very short lines.
	tailData  []byte
	tailStart int
	tailLines int64
	// tailSeen counts every line offered to tail. The retained lines are always
	// the newest ones, so fewer than min(Tail, tailSeen) means a requested line
	// was dropped for bytes.
	tailSeen int64
	lines    int64
}

func newFilterWriter(output *limitedOutput, options FilterOptions) *filterWriter {
	w := &filterWriter{output: output, options: options}
	if options.Match != "" {
		w.match = regexp.MustCompile(options.Match)
	}
	if options.Exclude != "" || options.excludeSet {
		w.exclude = regexp.MustCompile(options.Exclude)
	}
	return w
}
func (w *filterWriter) emit(line string) error {
	if w.options.Head > 0 && w.lines >= w.options.Head {
		return nil
	}
	w.lines++
	if w.options.Count {
		return nil
	}
	_, err := io.WriteString(w.output, line)
	return err
}

// dropOldest evicts the oldest retained line. The dead prefix is compacted
// once it outgrows the live part, which keeps eviction amortized O(1) and the
// backing array within about twice the retained bytes.
func (w *filterWriter) dropOldest() {
	rest := w.tailData[w.tailStart:]
	n := bytes.IndexByte(rest, '\n') + 1
	if n == 0 {
		n = len(rest)
	}
	w.tailStart += n
	w.tailLines--
	if live := len(w.tailData) - w.tailStart; w.tailStart > live {
		w.tailData = w.tailData[:copy(w.tailData, w.tailData[w.tailStart:])]
		w.tailStart = 0
	}
}

// trimTail drops the oldest lines until the retained bytes fit limit, always
// keeping the newest line so that the output limit cuts inside it.
func (w *filterWriter) trimTail(limit int64) {
	for w.tailLines > 1 && int64(len(w.tailData)-w.tailStart) > limit {
		w.dropOldest()
	}
}

func (w *filterWriter) Write(p []byte) (int, error) {
	line := string(p)
	text := strings.TrimSuffix(line, "\n")
	if (w.match != nil && !w.match.MatchString(text)) || (w.exclude != nil && w.exclude.MatchString(text)) {
		return len(p), nil
	}
	if w.options.Tail > 0 {
		w.tailData = append(w.tailData, p...)
		w.tailLines++
		w.tailSeen++
		if w.tailLines > w.options.Tail {
			w.dropOldest()
		}
		w.trimTail(w.output.limit)
		return len(p), nil
	}
	return len(p), w.emit(line)
}
func (w *filterWriter) finish() error {
	// A step shares its budget with other output, so the room left now can be
	// smaller than the limit; keep the newest lines that fit it.
	w.trimTail(w.output.room())
	if w.tailLines < min(w.options.Tail, w.tailSeen) {
		w.output.truncated = true
	}
	for rest := w.tailData[w.tailStart:]; len(rest) > 0; {
		n := bytes.IndexByte(rest, '\n') + 1
		if n == 0 {
			n = len(rest)
		}
		if err := w.emit(string(rest[:n])); err != nil {
			return err
		}
		rest = rest[n:]
	}
	if w.options.Count {
		_, err := io.WriteString(w.output, strconv.FormatInt(w.lines, 10)+"\n")
		return err
	}
	return nil
}

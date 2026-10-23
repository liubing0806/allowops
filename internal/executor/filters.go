package executor

import (
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

// match/exclude may combine with at most one result filter (decisions A17).
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

type filterWriter struct {
	output         io.Writer
	options        FilterOptions
	match, exclude *regexp.Regexp
	tail           []string
	next           int
	lines          int64
}

func newFilterWriter(output io.Writer, options FilterOptions) *filterWriter {
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
func (w *filterWriter) Write(p []byte) (int, error) {
	line := string(p)
	text := strings.TrimSuffix(line, "\n")
	if (w.match != nil && !w.match.MatchString(text)) || (w.exclude != nil && w.exclude.MatchString(text)) {
		return len(p), nil
	}
	if w.options.Tail > 0 {
		if int64(len(w.tail)) < w.options.Tail {
			w.tail = append(w.tail, line)
		} else {
			w.tail[w.next] = line
			w.next = (w.next + 1) % len(w.tail)
		}
		return len(p), nil
	}
	return len(p), w.emit(line)
}
func (w *filterWriter) finish() error {
	for i := range w.tail {
		if err := w.emit(w.tail[(w.next+i)%len(w.tail)]); err != nil {
			return err
		}
	}
	if w.options.Count {
		_, err := io.WriteString(w.output, strconv.FormatInt(w.lines, 10)+"\n")
		return err
	}
	return nil
}

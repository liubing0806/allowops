package logquery

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Levels are the values of the level parameter (design 6.4).
var Levels = []string{"ERROR", "WARN", "INFO", "DEBUG"}

// levelUnknown counts records whose first line has no level in by_level.
const levelUnknown = "UNKNOWN"

// Level is a source's optional level extraction rule (design 7.3). Regex must
// have a capture group named level and applies to the record's first line.
type Level struct {
	Regex string `json:"regex"`
}

// levelText bounds an extracted level, so by_level never carries log text.
var levelText = regexp.MustCompile(`^[A-Za-z]{1,16}$`)

type levelRule struct {
	re    *regexp.Regexp
	group int
}

func (l Level) compile() (*levelRule, error) {
	if l.Regex == "" {
		return nil, errors.New("regex required")
	}
	re, err := regexp.Compile(l.Regex)
	if err != nil {
		return nil, err
	}
	group := re.SubexpIndex("level")
	if group < 0 {
		return nil, errors.New("regex must have a capture group named level")
	}
	return &levelRule{re: re, group: group}, nil
}

// of returns the upper-case level of a record's first line, or levelUnknown.
func (r *levelRule) of(text string) string {
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		text = text[:i]
	}
	m := r.re.FindStringSubmatch(text)
	if m == nil || !levelText.MatchString(m[r.group]) {
		return levelUnknown
	}
	return strings.ToUpper(m[r.group])
}

// withLevels adds the level parameter to match. The returned rule is nil when
// the source declares no level rule; levels then fail with LEVEL_UNSUPPORTED.
func withLevels(source Source, levels []string, match func(string) bool) (func(string) bool, *levelRule, error) {
	var rule *levelRule
	if source.Level != nil {
		var err error
		if rule, err = source.Level.compile(); err != nil {
			return nil, nil, err
		}
	}
	if len(levels) == 0 {
		return match, rule, nil
	}
	if rule == nil {
		return nil, nil, codeError(CodeLevelUnsupported, "the source declares no level rule; omit level or match the level text with pattern")
	}
	for _, level := range levels {
		if !slices.Contains(Levels, level) {
			return nil, nil, fmt.Errorf("level allowed: %s", strings.Join(Levels, ", "))
		}
	}
	return func(text string) bool {
		return match(text) && slices.Contains(levels, rule.of(text))
	}, rule, nil
}

// anyLevel reports whether some source declares a level rule; the level
// parameter is offered only then.
func (c Config) anyLevel() bool {
	for _, source := range c.Sources {
		if source.Level != nil {
			return true
		}
	}
	return false
}

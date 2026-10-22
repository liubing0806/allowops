package redact

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
)

const DefaultMaxLine = 1024 * 1024

type Rule struct {
	Name  string `json:"name" yaml:"name"`
	Regex string `json:"regex" yaml:"regex"`
}

type Config struct {
	// nil enables secrets by default; an explicit empty slice disables builtins.
	Builtin []string `json:"builtin" yaml:"builtin"`
	Custom  []Rule   `json:"custom,omitempty" yaml:"custom,omitempty"`
}

type compiledRule struct {
	name  string
	re    *regexp.Regexp
	valid func(string) bool
	group int
}
type Redactor struct {
	rules   []compiledRule
	secrets bool
}

var pemBegin = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----`)
var pemEnd = regexp.MustCompile(`-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----`)

func New(config *Config) (*Redactor, error) {
	builtins := []string{"secrets"}
	if config != nil && config.Builtin != nil {
		builtins = config.Builtin
	}
	r := &Redactor{}
	for _, name := range builtins {
		if !slices.Contains([]string{"secrets", "pii"}, name) {
			return nil, fmt.Errorf("unknown redaction builtin %q; allowed: secrets, pii", name)
		}
	}
	if slices.Contains(builtins, "secrets") {
		r.secrets = true
		for _, rule := range []Rule{
			{"aliyun_access_key", `\bLTAI[A-Za-z0-9]{12,}\b`},
			{"aws_access_key", `\bAKIA[A-Z0-9]{16}\b`},
			{"jwt", `\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`},
			{"bearer", `(?i)Authorization\s*:\s*Bearer\s+[^\s]+`},
			{"url_credentials", `[A-Za-z][A-Za-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@`},
			{"mysql_pwd", `(?i)\bMYSQL_PWD\s*=\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s;]+)`},
			{"rediscli_auth", `(?i)\bREDISCLI_AUTH\s*=\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s;]+)`},
			{"credential", `(?i)\b(?:password|secret|token)\s*=\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s;]+)`},
		} {
			r.rules = append(r.rules, compiledRule{name: rule.Name, re: regexp.MustCompile(rule.Regex)})
		}
		// Keep the boundary out of the replacement; -p without a value stays unchanged.
		r.rules = append(r.rules, compiledRule{name: "mysql_password", re: regexp.MustCompile(`(?:^|[\s])(-p(?:"[^"\r\n]+"|'[^'\r\n]+'|[^\s]+))`), group: 1})
	}
	if slices.Contains(builtins, "pii") {
		// A digit boundary is checked separately, since Go RE2 has no lookbehind.
		r.rules = append(r.rules,
			compiledRule{name: "identity_card", re: regexp.MustCompile(`[0-9]{17}[0-9Xx]`), valid: validIdentity},
			compiledRule{name: "bank_card", re: regexp.MustCompile(`[0-9]{13,19}`), valid: validLuhn},
			compiledRule{name: "phone", re: regexp.MustCompile(`1[3-9][0-9]{9}`), valid: func(string) bool { return true }},
		)
	}
	if config != nil {
		for _, rule := range config.Custom {
			if rule.Name == "" || strings.ContainsAny(rule.Name, "\x00\r\n[]") {
				return nil, fmt.Errorf("custom redaction rule needs a valid name")
			}
			re, err := regexp.Compile(rule.Regex)
			if err != nil {
				return nil, fmt.Errorf("custom redaction %s: %w", rule.Name, err)
			}
			if re.MatchString("") {
				return nil, fmt.Errorf("custom redaction %s must not match empty input", rule.Name)
			}
			r.rules = append(r.rules, compiledRule{name: rule.Name, re: re})
		}
	}
	return r, nil
}

func replacement(name string) string { return "[REDACTED:" + name + "]" }
func digit(b byte) bool              { return b >= '0' && b <= '9' }

func applyRule(line string, rule compiledRule) string {
	matches := rule.re.FindAllStringSubmatchIndex(line, -1)
	if len(matches) == 0 {
		return line
	}
	var out strings.Builder
	cursor := 0
	for _, m := range matches {
		start, end := m[0], m[1]
		if rule.group > 0 {
			start, end = m[rule.group*2], m[rule.group*2+1]
		}
		if start < 0 {
			continue
		}
		if rule.valid != nil {
			if (start > 0 && digit(line[start-1])) || (end < len(line) && digit(line[end])) || !rule.valid(line[start:end]) {
				continue
			}
		}
		out.WriteString(line[cursor:start])
		out.WriteString(replacement(rule.name))
		cursor = end
	}
	if cursor == 0 {
		return line
	}
	out.WriteString(line[cursor:])
	return out.String()
}

func (r *Redactor) Line(line string) string {
	if r.secrets {
		inside := false
		line = r.pemLine(line, &inside)
	}
	for _, rule := range r.rules {
		line = applyRule(line, rule)
	}
	return line
}

func (r *Redactor) pemLine(line string, inside *bool) string {
	var out strings.Builder
	for {
		if *inside {
			end := pemEnd.FindStringIndex(line)
			if end == nil {
				return out.String()
			}
			line = line[end[1]:]
			*inside = false
		} else {
			begin := pemBegin.FindStringIndex(line)
			if begin == nil {
				out.WriteString(line)
				return out.String()
			}
			out.WriteString(line[:begin[0]])
			out.WriteString(replacement("pem_private_key"))
			line = line[begin[1]:]
			*inside = true
		}
	}
}

// Stream retains at most maxLine bytes of one original line. Overlong lines fail closed.
// PEM state is local to each stream so one Redactor can handle stdout/stderr concurrently.
func (r *Redactor) Stream(input io.Reader, output io.Writer, maxLine int) error {
	if maxLine <= 0 {
		return fmt.Errorf("maximum line length must be positive")
	}
	reader := bufio.NewReaderSize(input, min(maxLine+1, 64*1024))
	inside := false
	for {
		var line []byte
		var readErr error
		for {
			chunk, err := reader.ReadSlice('\n')
			if len(line)+len(chunk) > maxLine+1 {
				return fmt.Errorf("output line exceeds maximum length %d", maxLine)
			}
			line = append(line, chunk...)
			if err != bufio.ErrBufferFull {
				readErr = err
				break
			}
		}
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		if len(line) == 0 && readErr == io.EOF {
			return nil
		}
		newline := bytes.HasSuffix(line, []byte("\n"))
		if newline {
			line = line[:len(line)-1]
		}
		if len(line) > maxLine {
			return fmt.Errorf("output line exceeds maximum length %d", maxLine)
		}
		text := string(line)
		if r.secrets {
			text = r.pemLine(text, &inside)
		}
		for _, rule := range r.rules {
			text = applyRule(text, rule)
		}
		if newline {
			text += "\n"
		}
		if _, err := io.WriteString(output, text); err != nil {
			return err
		}
		if readErr == io.EOF {
			return nil
		}
	}
}

func validIdentity(s string) bool {
	if len(s) != 18 {
		return false
	}
	weights := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	checks := "10X98765432"
	total := 0
	for i, w := range weights {
		if !digit(s[i]) {
			return false
		}
		total += int(s[i]-'0') * w
	}
	return strings.ToUpper(s[17:]) == string(checks[total%11])
}

func validLuhn(s string) bool {
	if len(s) < 13 || len(s) > 19 {
		return false
	}
	sum := 0
	double := false
	nonzero := false
	for i := len(s) - 1; i >= 0; i-- {
		n := int(s[i] - '0')
		if n > 0 {
			nonzero = true
		}
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return nonzero && sum%10 == 0
}

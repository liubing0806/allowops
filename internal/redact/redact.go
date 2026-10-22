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
	// keep reports that a matched text is known not to be a secret and must stay.
	keep func(string) bool
	// needs lists lower-case substrings; one of them must occur in the line,
	// otherwise the expression cannot match and is not run. It is a speed-up
	// only and must be a necessary condition of the expression.
	needs []string
	group int
}
type Redactor struct {
	rules   []compiledRule
	secrets bool
}

var pemBegin = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----`)
var pemEnd = regexp.MustCompile(`-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----`)

// Credential key names for the colon and equals forms. A key must end with
// one of these words, so token_count, max_tokens, SecretName and
// TokenExpirationSeconds stay readable, and bare "key" is not a credential.
const credentialWords = `password|passwd|passphrase|secret|token|credentials?|(?:api|access|secret|private|auth|encryption|signing|master)[_-]?key|apikey`

// Value of a command-line option: a quoted string, or a word that does not
// start with '-' (so a following option is never taken as the value).
const optionValue = `("[^"\r\n]*"|'[^'\r\n]*'|[^\s"'-]\S*)`

type secretRule struct {
	name  string
	regex string
	needs []string
	keep  func(string) bool
	group int
}

// Rules are applied in order. Specific markers (bearer, url_credentials,
// auth_header ...) come before the generic credential rules, so a header or
// URL keeps its own marker.
var secretRules = []secretRule{
	{name: "aliyun_access_key", needs: []string{"ltai"}, regex: `\bLTAI[A-Za-z0-9]{12,}\b`},
	{name: "aws_access_key", needs: []string{"akia"}, regex: `\bAKIA[A-Z0-9]{16}\b`},
	{name: "jwt", needs: []string{"eyj"}, regex: `\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`},
	{name: "bearer", needs: []string{"bearer"}, regex: `(?i)Authorization\s*:\s*Bearer\s+[^\s]+`},
	// The user name may be empty (redis://:password@host). The password runs to
	// the last '@' of the token, so a password containing '@' is covered; it
	// cannot contain '/' or a quote, which end the match.
	{name: "url_credentials", needs: []string{"://"}, regex: `[A-Za-z][A-Za-z0-9+.-]*://[^\s/@:]*:[^\s/"']+@`},
	// Oracle thin: jdbc:oracle:thin:user/password@host
	{name: "url_credentials", needs: []string{"jdbc:oracle"}, regex: `(?i)\bjdbc:oracle:(?:thin|oci8?):[^\s/@:"']+/[^\s"']+@`},
	{name: "mysql_pwd", needs: []string{"mysql_pwd"}, regex: `(?i)\bMYSQL_PWD\s*=\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s;]+)`},
	{name: "rediscli_auth", needs: []string{"rediscli_auth"}, regex: `(?i)\bREDISCLI_AUTH\s*=\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s;]+)`},
	{name: "credential", needs: []string{"password", "secret", "token"}, regex: `(?i)\b(?:password|secret|token)\s*=\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s;]+)`},
	{name: "auth_header", needs: []string{"authorization"}, regex: `(?i)\b(?:proxy-)?authorization["']?\s*:\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\r\n]*)|\b(?:proxy_set_header|add_header|more_set_headers|set_header)\s+["']?(?:proxy-)?authorization["']?\s+[^;\r\n]*`},
	{name: "api_key_header", needs: []string{"x-", "set_header", "add_header"}, regex: `(?i)\bx-[A-Za-z0-9-]*(?:key|token|secret|auth|pass|pwd|credential)[A-Za-z0-9-]*["']?\s*:\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\r\n]*)|\b(?:proxy_set_header|add_header|more_set_headers|set_header)\s+["']?[A-Za-z0-9_-]*(?:key|token|secret|pass|pwd|credential)[A-Za-z0-9_-]*["']?\s+[^;\r\n]*`},
	{name: "htpasswd_hash", needs: []string{"$", "sha"}, regex: `\$(?:apr1|1|5|6|2[abxy]|y|7)\$(?:[./0-9A-Za-z,=]+\$)+[./0-9A-Za-z]{20,}|\{S?SHA(?:256|512)?\}[A-Za-z0-9+/=]{20,}`},
	// NAME=value with a prefixed key: DB_PASSWORD=x, AWS_SECRET_ACCESS_KEY=x,
	// access_token=x. A bare PWD or OLDPWD (working directory) is not matched.
	{name: "credential", needs: []string{"password", "passwd", "passphrase", "secret", "token", "credential", "key", "pwd"}, regex: `(?i)[A-Za-z0-9_.-]*(?:` + credentialWords + `|[_.-]pwd)\\?["']?\s*=\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s;]+)`},
	// NAME: value, such as the Environment section of kubectl describe pod,
	// YAML and JSON. A quoted value ends at the closing quote; an unquoted
	// value runs to the end of the line.
	{name: "credential", needs: []string{"password", "passwd", "passphrase", "secret", "token", "credential", "key", "pwd"}, regex: `(?i)[A-Za-z0-9_.-]*(?:` + credentialWords + `|pwd)\\?["']?\s*:\s*(?:"(?:[^"\\\r\n]|\\.)*"|'[^'\r\n]*'|\S.*)`, keep: describeSecretReference},
	// Command lines. Options that are also used with other meanings (-u, -a,
	// -p) are only recognised after the command that gives them a password.
	{name: "cli_password", needs: []string{"--"}, regex: `(?i)(?:^|\s)--(?:[a-z0-9]+-)*(?:password|passwd|pass|pwd|secret|token|api-?key|passphrase|requirepass|masterauth|bindpw)(?:\s+|=)` + optionValue, keep: negatedOption, group: 1},
	// The same options as elements of a JSON array: ["--requirepass","value"].
	{name: "cli_password", needs: []string{`"--`}, regex: `(?i)"--(?:[a-z0-9]+-)*(?:password|passwd|pass|pwd|secret|token|api-?key|passphrase|requirepass|masterauth|bindpw)"\s*,\s*"((?:[^"\\]|\\.)*)"`, keep: negatedOption, group: 1},
	{name: "cli_password", needs: []string{"curl"}, regex: `(?i)\bcurl\b[^\r\n]*?\s-(?:-user|-proxy-user|[A-Za-z]*[uU])(?:\s+|=)("[^"\r\n]*:[^"\r\n]*"|'[^'\r\n]*:[^'\r\n]*'|[^\s:"']+:\S*)`, group: 1},
	{name: "cli_password", needs: []string{"redis-cli", "valkey-cli"}, regex: `(?i)\b(?:redis|valkey)-cli\b[^\r\n]*?\s-a\s+("[^"\r\n]*"|'[^'\r\n]*'|\S+)`, group: 1},
	{name: "cli_password", needs: []string{"sshpass"}, regex: `(?i)\bsshpass\b[^\r\n]*?\s-p\s+("[^"\r\n]*"|'[^'\r\n]*'|\S+)`, group: 1},
	// Keep the boundary out of the replacement; -p without a value stays unchanged.
	{name: "mysql_password", needs: []string{"-p"}, regex: `(?:^|[\s])(-p(?:"[^"\r\n]+"|'[^'\r\n]+'|[^\s]+))`, group: 1},
}

// kubectl describe prints a reference to a secret or config map instead of the
// value for valueFrom variables; the reference names no secret data.
var describeReference = regexp.MustCompile(`^[^:]*:\s*<set to the key '[^']*' (?:in|of) (?:secret|config map) '[^']*'>\s+Optional: (?:true|false)$`)

func describeSecretReference(match string) bool { return describeReference.MatchString(match) }

var negatedOptionName = regexp.MustCompile(`(?i)^\s*"?--(?:no|ask|skip|disable|without)-`)

// negatedOption reports flags such as --no-password or --ask-pass, which take no value.
func negatedOption(match string) bool { return negatedOptionName.MatchString(match) }

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
		for _, rule := range secretRules {
			r.rules = append(r.rules, compiledRule{name: rule.name, re: regexp.MustCompile(rule.regex), keep: rule.keep, needs: rule.needs, group: rule.group})
		}
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
		if rule.keep != nil && rule.keep(line[m[0]:m[1]]) {
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
	return r.applyRules(line)
}

// applyRules runs the rules in order. A rule with needs is skipped when the
// line cannot contain a match; non-ASCII lines run every rule, because
// case-insensitive expressions also match characters such as U+017F.
func (r *Redactor) applyRules(line string) string {
	lower, lowered, ascii := "", false, isASCII(line)
	for _, rule := range r.rules {
		if ascii && len(rule.needs) > 0 {
			if !lowered {
				lower, lowered = strings.ToLower(line), true
			}
			if !containsAny(lower, rule.needs) {
				continue
			}
		}
		if next := applyRule(line, rule); next != line {
			line, lowered, ascii = next, false, isASCII(next)
		}
	}
	return line
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func containsAny(s string, needs []string) bool {
	for _, n := range needs {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
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
		text = r.applyRules(text)
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

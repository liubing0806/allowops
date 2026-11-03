package sqlguard

import (
	"strings"
	"unicode/utf8"
)

type tokKind uint8

const (
	tWord   tokKind = iota + 1 // unquoted identifier or keyword; text is upper case
	tNumber                    // run of ASCII digits; letters after it start a new word
	tString                    // quoted literal; text is the raw content without the quotes
	tQuoted                    // quoted identifier; text is the content with doubled quotes folded
	tPunct                     // operator or punctuation; text is the symbol
)

type token struct {
	kind tokKind
	text string
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isLetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

func isPunct(t token, s string) bool { return t.kind == tPunct && t.text == s }

// lex splits s into tokens and drops whitespace and comments. It rejects every
// spelling whose boundaries the server may read differently, see the package
// documentation.
func lex(d Dialect, s string) ([]token, error) {
	var toks []token
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case isSpace(c):
			i++
		case c >= utf8.RuneSelf:
			return nil, reject("non-ASCII character outside a quoted string or identifier")
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			// Lexers disagree on "--" without whitespace: MySQL needs the whitespace, StarRocks 3.3 does not
			// ("SELECT 1--1" returns 1). Accept only the spelling that is a comment everywhere.
			if i+2 >= len(s) || !isSpace(s[i+2]) {
				return nil, reject("-- must be followed by whitespace")
			}
			end, err := lineComment(s, i+2)
			if err != nil {
				return nil, err
			}
			i = end
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end, err := blockComment(s, i)
			if err != nil {
				return nil, err
			}
			i = end
		case c == '/' && i+1 < len(s) && s[i+1] == '/':
			// Calcite-based lexers read "//" as a line comment, so a quote after it is invisible to the
			// server but opens a string for the guard. No SQL here needs the sequence.
			return nil, reject("// is not allowed")
		case c == '\'' || (c == '"' && d == StarRocks):
			// StarRocks reads both quotes as string literals with backslash escapes; Dremio has only ''.
			raw, next, ok := scanQuoted(s, i, d == StarRocks)
			if !ok {
				return nil, reject("unterminated string literal")
			}
			if err := blockOpenerInQuotes(d, s, i+1, raw); err != nil {
				return nil, err
			}
			toks = append(toks, token{tString, raw})
			i = next
		case c == '"' || c == '`':
			if c == '`' && d != StarRocks {
				return nil, reject("backquote is not allowed in this dialect")
			}
			raw, next, ok := scanQuoted(s, i, false)
			if !ok {
				return nil, reject("unterminated quoted identifier")
			}
			if err := blockOpenerInQuotes(d, s, i+1, raw); err != nil {
				return nil, err
			}
			q := string(c)
			toks = append(toks, token{tQuoted, strings.ReplaceAll(raw, q+q, q)})
			i = next
		case isLetter(c):
			j := i + 1
			for j < len(s) && (isLetter(s[j]) || isDigit(s[j])) {
				j++
			}
			toks = append(toks, token{tWord, strings.ToUpper(s[i:j])})
			i = j
		case isDigit(c):
			j := i + 1
			for j < len(s) && isDigit(s[j]) {
				j++
			}
			toks = append(toks, token{tNumber, s[i:j]})
			i = j
		default:
			switch c {
			case '(', ')', ',', '.', ';', '*', '+', '-', '/', '%', '=', '<', '>', '!', '|', '&', '^', '~', '[', ']':
			case ':':
				if i+1 < len(s) && s[i+1] == '=' {
					return nil, reject(":= assignment is not allowed")
				}
			case '@', '{', '}':
				// System variables and MAP{...} literals exist only in StarRocks.
				if d != StarRocks {
					return nil, reject("character is not allowed in this dialect")
				}
			case '#':
				// StarRocks 3.3 drops "#" and parses what follows, so it hides nothing but is not a comment either.
				return nil, reject("# is not allowed outside a quoted string or identifier")
			case '?':
				return nil, reject("parameter placeholder is not allowed")
			default:
				return nil, reject("character is not allowed outside a quoted string or identifier")
			}
			toks = append(toks, token{tPunct, string(c)})
			i++
		}
	}
	return toks, nil
}

// scanQuoted reads the quoted text that starts at s[i] and returns the content
// between the quotes and the index after the closing quote.
func scanQuoted(s string, i int, backslash bool) (raw string, next int, ok bool) {
	q := s[i]
	for j := i + 1; j < len(s); j++ {
		switch {
		case backslash && s[j] == '\\':
			j++ // the escaped byte cannot close the literal
		case s[j] == q:
			if j+1 < len(s) && s[j+1] == q {
				j++
				continue
			}
			return s[i+1 : j], j + 1, true
		}
	}
	return "", len(s), false
}

// lineComment returns the index of the terminator of the comment whose body
// starts at from. Both CR and LF end it, so a server that ends it only at LF
// sees a subset of what the guard sees.
func lineComment(s string, from int) (int, error) {
	end := len(s)
	if k := strings.IndexAny(s[from:], "\r\n"); k >= 0 {
		end = from + k
	}
	if hasSetVar(s[from:end]) {
		return 0, reject("set_var in a comment is not allowed")
	}
	return end, nil
}

func blockComment(s string, i int) (int, error) {
	rest := s[i+2:]
	switch {
	case strings.HasPrefix(rest, "+"):
		return 0, reject("optimizer hint comment is not allowed")
	case strings.HasPrefix(rest, "!"), strings.HasPrefix(rest, "M!"), strings.HasPrefix(rest, "m!"):
		return 0, reject("executable comment is not allowed")
	}
	k := strings.Index(rest, "*/")
	if k < 0 {
		return 0, reject("unterminated comment")
	}
	// The star of the terminator is included so that "/*/" is read as a nested opener.
	if strings.Contains(rest[:k+1], "/*") {
		return 0, reject("nested comment is not allowed")
	}
	if hasSetVar(rest[:k]) {
		return 0, reject("set_var in a comment is not allowed")
	}
	return i + 2 + k + 2, nil
}

// blockOpenerInQuotes rejects a "/*" inside a Dremio string or quoted
// identifier when set_var occurs anywhere after it. Dremio 24.1 cuts "/* ... */"
// comments out of the raw statement text with a regular expression that
// ignores quoting and turns the set_var.x=v entries in them into a SET_VAR hint
// of the pushed-down query. Such a comment can span several strings
// ('/*' ... 'set_var.x=v */'), so the search for set_var covers the rest of the
// statement and not only the quoted text. content starts at s[from].
func blockOpenerInQuotes(d Dialect, s string, from int, content string) error {
	if d != Dremio {
		return nil
	}
	k := strings.Index(content, "/*")
	if k >= 0 && hasSetVar(s[from+k+2:]) {
		return reject("set_var after /* inside a quoted string or identifier is not allowed")
	}
	return nil
}

func hasSetVar(comment string) bool {
	return strings.Contains(strings.ToLower(comment), "set_var")
}

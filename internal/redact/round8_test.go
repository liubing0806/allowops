package redact

import "testing"

// A URL inside a quoted string whose password holds an escaped quote: a doubled
// quote in a single-quoted YAML string, a backslash escape in a double-quoted
// JSON or YAML string. The escaped quote is part of the password, the closing
// quote still ends the URL.
func TestURLPasswordWithEscapedQuote(t *testing.T) {
	r := builtinOnly(t)
	checkSecretCases(t, r, []secretCase{
		{`url: 'postgres://u:abc''LEAK@h/db'`, "LEAK"},
		{`url: 'postgres://u:''LEAK@h/db'`, "LEAK"},
		{`{'url':'postgres://u:abc''LEAK@h/db','mail':'a@b.com'}`, "LEAK"},
		{`{"url":"postgres://u:abc\"LEAK@h/db"}`, "LEAK"},
		{`url: "postgres://u:abc\"LEAK@h/db"`, "LEAK"},
		{`{"url":"postgres://u:abc\\\"LEAK@h/db","mail":"a@b.com"}`, "LEAK"},
	})
	checkExact(t, r, [][2]string{
		{`url: 'postgres://u:abc''LEAK@h/db'`, `url: '[REDACTED:url_credentials]h/db'`},
		{`{'url':'postgres://u:abc''LEAK@h/db','mail':'a@b.com'}`, `{'url':'[REDACTED:url_credentials]h/db','mail':'a@b.com'}`},
		{`{"url":"postgres://u:abc\"LEAK@h/db","mail":"a@b.com"}`, `{"url":"[REDACTED:url_credentials]h/db","mail":"a@b.com"}`},
		{`{'url':'redis://:pw@h','mail':'a@b.com'}`, `{'url':'[REDACTED:url_credentials]h','mail':'a@b.com'}`},
		{`{"a":"b://c","d":"e@f"}`, `{"a":"b://c","d":"e@f"}`},
		{`{'a':'b://c','d':'e@f'}`, `{'a':'b://c','d':'e@f'}`},
		{`{"a":"b://c:\"x","d":"e@f"}`, `{"a":"b://c:\"x","d":"e@f"}`},
	})
}

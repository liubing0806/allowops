package redact

import (
	"slices"
	"strings"
	"testing"
)

func TestLineSecrets(t *testing.T) {
	r, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		line string
		want []string
	}{
		{"password=x", []string{"x"}},
		{"key: x", []string{"x"}},
		{"db-password: 'with spaces'", []string{"with spaces"}},
		{"--password x", []string{"x"}},
		{"curl -u user:password https://example.invalid", []string{"user:password", "password"}},
		{`["curl","-u","user:password"]`, []string{"user:password", "password"}},
		{"user:password@tcp(example.invalid:3306)/db", []string{"user:password@", "password"}},
		{"--password='with spaces'", []string{"with spaces"}},
		{"Authorization: Bearer tok", []string{"tok"}},
		{"Proxy-Authorization: Basic abc==", []string{"abc=="}},
		{"https://u:p@h", []string{"u:p@", "p"}},
		{"eyJabc.def.ghi", []string{"eyJabc.def.ghi"}},
		{"AKIA0123456789ABCDEF", []string{"AKIA0123456789ABCDEF"}},
		{"LTAI0123456789abcdef", []string{"LTAI0123456789abcdef"}},
		{"-px", []string{"x"}},
		{"-p", nil},
		{`{"password":"c1","token":"c2"}`, []string{"c1", "c2"}},
		{"Authorization: Bearer eyJabc.def.ghi", []string{"eyJabc.def.ghi"}},
		{"password: label eyJabc.def.ghi", []string{"eyJabc.def.ghi", "label eyJabc.def.ghi"}},
		{"-----BEGIN PRIVATE KEY-----payload-----END PRIVATE KEY-----", []string{"payload"}},
		{"DB_PASSWORD: <set to the key 'password' in secret 'db'> Optional: false", nil},
	} {
		t.Run(tc.line, func(t *testing.T) {
			clean, got := r.LineSecrets(tc.line)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("secrets = %q, want %q", got, tc.want)
			}
			if !strings.HasPrefix(tc.line, "key:") && clean != r.Line(tc.line) {
				t.Fatalf("clean = %q, want %q", clean, r.Line(tc.line))
			}
			if len(tc.want) > 0 && !strings.Contains(clean, "[REDACTED:") {
				t.Fatalf("missing redaction marker: %q", clean)
			}
		})
	}
}

func TestLineSecretsOnlyExtractsBuiltinSecrets(t *testing.T) {
	r, err := New(&Config{Builtin: []string{"pii"}, Custom: []Rule{{Name: "custom", Regex: "example"}}})
	if err != nil {
		t.Fatal(err)
	}
	clean, secrets := r.LineSecrets("password=x example")
	if clean != "password=x [REDACTED:custom]" || len(secrets) != 0 {
		t.Fatalf("clean = %q, secrets = %q", clean, secrets)
	}
}

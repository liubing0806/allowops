package redact

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuiltinSecrets(t *testing.T) {
	r, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		"-----BEGIN PRIVATE KEY-----\nabcdef\n-----END PRIVATE KEY-----\n",
		"-----BEGIN RSA PRIVATE KEY-----\nabcdef\n-----END RSA PRIVATE KEY-----",
		"LTAI1234567890abcdefghijkl", "AKIA1234567890ABCDEF",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
		"Authorization: Bearer opaque-token", "https://alice:password@example.com/a",
		"password=hello secret='two words' token=abc", "mysql -psecret -h localhost", "MYSQL_PWD=secret REDISCLI_AUTH=secret",
	} {
		var out bytes.Buffer
		if err := r.Stream(strings.NewReader(input), &out, DefaultMaxLine); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "[REDACTED:") || strings.Contains(out.String(), "abcdef") || strings.Contains(out.String(), "opaque-token") || strings.Contains(out.String(), "two words") {
			t.Fatalf("%q => %q", input, out.String())
		}
	}
	for _, input := range []string{"AKIB1234567890ABCDEF", "LTAshort", "password is unset", "mysql -p -h localhost", "http://example.com", "10.0.0.1 host.example.com"} {
		if got := r.Line(input); got != input {
			t.Fatalf("%q => %q", input, got)
		}
	}
}

func TestSecretRuleExamples(t *testing.T) {
	r, _ := New(nil)
	for _, tc := range []struct{ input, want string }{
		{"LTAI1234567890abcdefghijkl", "[REDACTED:aliyun_access_key]"},
		{"AKIA1234567890ABCDEF", "[REDACTED:aws_access_key]"},
		{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature", "[REDACTED:jwt]"},
		{"Authorization: Bearer opaque-token", "[REDACTED:bearer]"},
		{"https://alice:password@example.com/a", "[REDACTED:url_credentials]example.com/a"},
		{"password=hello secret='two words' token=abc", "[REDACTED:credential] [REDACTED:credential] [REDACTED:credential]"},
		{"mysql -psecret -h localhost", "mysql [REDACTED:mysql_password] -h localhost"},
		{"MYSQL_PWD=secret REDISCLI_AUTH=secret", "[REDACTED:mysql_pwd] [REDACTED:rediscli_auth]"},
		{"Authorization: Basic abc", "[REDACTED:auth_header]"},
		{"eyJheader.payload", "eyJheader.payload"},
		{"https://alice@example.com/a", "https://alice@example.com/a"},
		{"MYSQL_PWD", "MYSQL_PWD"}, {"REDISCLI_AUTH", "REDISCLI_AUTH"},
	} {
		if got := r.Line(tc.input); got != tc.want {
			t.Fatalf("%q => %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestPIIChecksumsAndCustom(t *testing.T) {
	r, err := New(&Config{Builtin: []string{"pii"}, Custom: []Rule{{Name: "order_token", Regex: `otk_[A-Z]{4}`}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"13800138000", "11010519491231002X", "4111111111111111", "otk_ABCD"} {
		if got := r.Line(input); !strings.Contains(got, "[REDACTED:") {
			t.Fatalf("not redacted: %q", got)
		}
	}
	for _, input := range []string{"12800138000", "110105194912310021", "4111111111111112", "otk_abc", "113800138000", "AKIA1234567890ABCDEF"} {
		if got := r.Line(input); got != input {
			t.Fatalf("false positive %q => %q", input, got)
		}
	}
	if _, err := New(&Config{Custom: []Rule{{Name: "invalid", Regex: "["}}}); err == nil {
		t.Fatal("accepted invalid RE2")
	}
	if _, err := New(&Config{Builtin: []string{"typo"}}); err == nil {
		t.Fatal("accepted unknown builtin")
	}
}

func TestStreamBoundAndPEM(t *testing.T) {
	r, _ := New(nil)
	var out bytes.Buffer
	if err := r.Stream(strings.NewReader(strings.Repeat("x", 10000)), &out, 128); err == nil || out.Len() != 0 {
		t.Fatalf("length=%d err=%v", out.Len(), err)
	}
	out.Reset()
	input := "before\n-----BEGIN EC PRIVATE KEY-----\nsecret-body\n-----END EC PRIVATE KEY-----\nafter\n"
	if err := r.Stream(strings.NewReader(input), &out, 128); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "secret-body") || !strings.HasSuffix(out.String(), "after\n") {
		t.Fatal(out.String())
	}
	disabled, _ := New(&Config{Builtin: []string{}})
	if got := disabled.Line("password=abc"); got != "password=abc" {
		t.Fatal(got)
	}
}

func TestD9Credentials(t *testing.T) {
	r, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ input, want string }{
		{"mysql -psecret", "mysql [REDACTED:mysql_password]"},
		{`mysql -p"two words"`, "mysql [REDACTED:mysql_password]"},
		{"MYSQL_PWD='two words' mysql", "[REDACTED:mysql_pwd] mysql"},
		{"REDISCLI_AUTH=secret redis-cli", "[REDACTED:rediscli_auth] redis-cli"},
		{"mysql -p -h localhost", "mysql -p -h localhost"},
		{"ordinary-pvalue", "ordinary-pvalue"},
	} {
		if got := r.Line(tc.input); got != tc.want {
			t.Errorf("%q => %q; want %q", tc.input, got, tc.want)
		}
	}
}

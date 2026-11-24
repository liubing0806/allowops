package redact

import (
	"strings"
	"testing"
)

func TestEscapedSecretBoundaries(t *testing.T) {
	r := builtinOnly(t)
	for _, tc := range []struct{ input, want string }{
		{`status=ok\nAKIA1234567890ABCDEF\tLTAI1234567890abcd\reyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig`,
			`status=ok\n[REDACTED:aws_access_key]\t[REDACTED:aliyun_access_key]\r[REDACTED:jwt]`},
		{`{"message":"{\n\t\"password\" : \"example\\\"value\",\n\t\"user\":\"bob\"}"}`,
			`{"message":"{\n\t[REDACTED:credential],\n\t\"user\":\"bob\"}"}`},
		{`{"message":"\"password\":\"example\"","user":"bob"}`,
			`{"message":"[REDACTED:credential]","user":"bob"}`},
		{`\n\"Authorization\":\t\"Bearer example\",\"status\":200`,
			`\n[REDACTED:auth_header],\"status\":200`},
		{`\n\"X-API-Key\":\t\"example\",\"status\":200`,
			`\n[REDACTED:api_key_header],\"status\":200`},
		{`status=ok\nREDISCLI_AUTH=example`, `status=ok\n[REDACTED:rediscli_auth]`},
		{`status=ok\tMYSQL_PWD=example`, `status=ok\t[REDACTED:mysql_pwd]`},
		{`status=ok\nAuthorization=example`, `status=ok\n[REDACTED:auth_header]`},
		{`status=ok\nredis-cli -a example`, `status=ok\nredis-cli -a [REDACTED:cli_password]`},
		{`status=ok\t--requirepass=example`, `status=ok\t--requirepass=[REDACTED:cli_password]`},
		{`status=ok\t--no-password --quiet`, `status=ok\t--no-password --quiet`},
		{`{"message":"{\n\t\"token_count\":5,\"user\":\"bob\"}"}`,
			`{"message":"{\n\t\"token_count\":5,\"user\":\"bob\"}"}`},
		{`status=ok\ntraceAKIA1234567890ABCDEF`, `status=ok\ntraceAKIA1234567890ABCDEF`},
	} {
		if got := r.Line(tc.input); got != tc.want {
			t.Errorf("%q => %q; want %q", tc.input, got, tc.want)
		}
	}
	line := strings.Repeat(`\n`, DefaultMaxLine/2-32) + `\tAKIA1234567890ABCDEF`
	want := strings.TrimSuffix(line, "AKIA1234567890ABCDEF") + "[REDACTED:aws_access_key]"
	if got := r.Line(line); got != want {
		t.Error("escaped boundaries in a maximum-size line changed surrounding text or retained the credential")
	}
}

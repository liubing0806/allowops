package redact

import (
	"math/rand"
	"strings"
	"testing"
)

// The needs filter only skips work. Whatever it skips must be output the rule
// would not have changed, for ASCII and for non-ASCII lines.
func TestRuleNeedsNeverChangeTheResult(t *testing.T) {
	full, err := New(&Config{Builtin: []string{"secrets", "pii"}})
	if err != nil {
		t.Fatal(err)
	}
	slow, _ := New(&Config{Builtin: []string{"secrets", "pii"}})
	for i := range slow.rules {
		slow.rules[i].needs = nil
	}
	words := []string{
		"password", "Password", "PASSWD", "passphrase", "secret", "TOKEN", "token", "credential", "credentials",
		"api_key", "apiKey", "access-key", "secret_key", "private_key", "pwd", "PWD", "DB_PWD", "key", "x-api-key", "X-Auth-Token",
		"Authorization", "Bearer", "Basic", "proxy_set_header", "add_header", "more_set_headers", "set_header",
		"curl", "-u", "-s", "--user", "--proxy-user", "redis-cli", "valkey-cli", "-a", "sshpass", "-p", "--requirepass", "--password", "--no-password",
		"jdbc:oracle:thin:", "scott/pw@", "redis://", ":pw@", "mysql_pwd", "REDISCLI_AUTH", "MYSQL_PWD",
		"$apr1$abcd1234$AbCdEfGhIjKlMnOpQrStU.", "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=", "$6$", "LTAI1234567890abcdefghijkl", "AKIA1234567890ABCDEF",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "13800138000", "4111111111111111",
		"=", ":", " ", "  ", "\"", "'", ",", ";", "value", "v@lue", "/", "@", "[", "]", "-", "_", ".",
		"pas\u017Fword", "\u212A", "s\u017Fecret", "中文",
	}
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 8000; i++ {
		var b strings.Builder
		for n := rng.Intn(9) + 1; n > 0; n-- {
			b.WriteString(words[rng.Intn(len(words))])
			if rng.Intn(3) == 0 {
				b.WriteByte(' ')
			}
		}
		line := b.String()
		if got, want := full.Line(line), slow.Line(line); got != want {
			t.Fatalf("%q: filtered %q, unfiltered %q", line, got, want)
		}
	}
}

func TestNonASCIICaseFoldingStillMatches(t *testing.T) {
	r := builtinOnly(t)
	for _, line := range []string{"pas\u017Fword=hunter2", "db_pas\u017Fword: hunter2", "s\u017Fecret=hunter2", "to\u212Aen=hunter2"} {
		if got := r.Line(line); strings.Contains(got, "hunter2") {
			t.Errorf("%q => %q", line, got)
		}
	}
}

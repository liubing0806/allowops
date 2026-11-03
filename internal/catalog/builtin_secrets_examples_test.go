package catalog

import (
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/redact"
)

// Credential forms from the round 4 review (redaction/F1, F3, F5, F6). They
// appear in files, logs, kubectl describe output and crontab lines, so every
// example action must hide them with the built-in secrets rules alone.
var builtinSecretCases = []redactionCase{
	// F1
	{"spring.redis.url=redis://:RedisPw123@10.0.0.5:6379/0", "RedisPw123"},
	{"spring.datasource.url=jdbc:oracle:thin:scott/OraPw456@10.0.0.6:1521:ORCL", "OraPw456"},
	{"spring.datasource.url2=jdbc:mysql://root:p@ss@db:3306/x", "ss@db"},
	{"redis conn redis://:LogRedisPw@10.0.0.5:6379", "LogRedisPw"},
	{"REDIS_URL: redis://:RedisUrlPw@redis:6379/0", "RedisUrlPw"},
	// F3
	{`proxy_set_header Authorization "Basic dXNlcjpQYXNzMTIz";`, "dXNlcjpQYXNzMTIz"},
	{"proxy_set_header X-Api-Key abc123secretvalue;", "abc123secretvalue"},
	{"add_header X-Auth-Token tok123456;", "tok123456"},
	{"admin:$apr1$abcd1234$AbCdEfGhIjKlMnOpQrStU.", "AbCdEfGhIjKlMnOpQrStU"},
	{"bob:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=", "W6ph5Mm5Pz8GgiULbPgzG37mj9g"},
	// F5
	{"      SPRING_DATASOURCE_PASSWORD:  Hunter2Prod", "Hunter2Prod"},
	{"      MYSQL_ROOT_PASSWORD:         RootPw1", "RootPw1"},
	{"      JWT_SECRET:                  jwtsecretvalue", "jwtsecretvalue"},
	{"      API_TOKEN:                   tok_live_abc123", "tok_live_abc123"},
	{"      AWS_SECRET_ACCESS_KEY:       wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI"},
	// F6
	{"*/5 * * * * curl -s -u admin:CurlPw1 http://127.0.0.1:8080/health", "CurlPw1"},
	{"0 3 * * * redis-cli -h 10.0.0.5 -a RedisCliPw2 bgsave", "RedisCliPw2"},
	{"0 9 * * * redis-server --requirepass SrvPw7", "SrvPw7"},
	{"0 7 * * * sshpass -p 'SshPw5' scp a b", "SshPw5"},
}

// Lines the built-in rules must leave alone. Actions with custom key-name rules
// (sensitive_property and others) deliberately redact more and are excluded.
var builtinReadableCases = []redactionCase{
	{"      DB_PASSWORD:  <set to the key 'password' in secret 'db-secret'>  Optional: false", ""},
	{"    SecretName:  db-secret", ""},
	{"PWD=/opt/app", ""},
	{"mysql -u root -h localhost", ""},
	{"docker exec -u 1000:1000 app sh", ""},
}

var nestedMarker = regexp.MustCompile(`\[REDACTED:[^\]]*\[REDACTED`)

func TestExampleActionsRedactBuiltinCredentialForms(t *testing.T) {
	c := loadExamples(t)
	names := make([]string, 0, len(c.Actions))
	for name := range c.Actions {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		checkRedactionCases(t, name, exampleRedactor(t, c, name), builtinSecretCases)
		if a := c.Actions[name]; a.Redact == nil || len(a.Redact.Custom) == 0 {
			checkRedactionCases(t, name, exampleRedactor(t, c, name), builtinReadableCases)
		}
	}
}

// Many example actions keep custom rules that now duplicate built-in ones.
// Whichever rule set runs first, the result must hide the secret, carry no
// nested or half-replaced marker, and be stable when redacted a second time.
func TestExampleCustomRulesComposeWithBuiltinRules(t *testing.T) {
	c := loadExamples(t)
	// Every action must hide the reviewed forms; the structured forms are checked
	// only for the actions that carry the matching custom rules.
	structured := append(append([]redactionCase{}, configCredentialCases...), hadoopStyleCases...)
	checked := 0
	for name, a := range c.Actions {
		if a.Redact == nil || len(a.Redact.Custom) == 0 {
			continue
		}
		checked++
		builtinOnly, err := redact.New(&redact.Config{Builtin: a.Redact.Builtin})
		if err != nil {
			t.Fatal(err)
		}
		customOnly, err := redact.New(&redact.Config{Builtin: []string{}, Custom: a.Redact.Custom})
		if err != nil {
			t.Fatal(err)
		}
		executor := exampleRedactor(t, c, name)
		leakCases := append([]redactionCase{}, builtinSecretCases...)
		switch {
		case slices.Contains(configReaders, name):
			leakCases = append(leakCases, structured...)
		case strings.HasSuffix(name, "_file_view") || strings.HasSuffix(name, "_file_grep"):
			leakCases = append(leakCases, fileCredentialCases...)
		}
		all := append(append(append([]redactionCase{}, leakCases...), structured...), fileCredentialCases...)
		for _, tc := range leakCases {
			for order, got := range map[string]string{
				"builtin then custom": executor.Line(tc.line),
				"custom then builtin": builtinOnly.Line(customOnly.Line(tc.line)),
			} {
				if tc.secret != "" && strings.Contains(got, tc.secret) {
					t.Errorf("%s (%s): %q leaks %q: %q", name, order, tc.line, tc.secret, got)
				}
			}
		}
		for _, tc := range all {
			for order, got := range map[string]string{
				"builtin then custom": executor.Line(tc.line),
				"custom then builtin": builtinOnly.Line(customOnly.Line(tc.line)),
			} {
				if nestedMarker.MatchString(got) {
					t.Errorf("%s (%s): %q gives a nested marker: %q", name, order, tc.line, got)
				}
			}
			if once := executor.Line(tc.line); executor.Line(once) != once {
				t.Errorf("%s: redacting %q twice changes the result: %q then %q", name, tc.line, once, executor.Line(once))
			}
		}
	}
	if checked < 10 {
		t.Fatalf("only %d example actions have custom rules", checked)
	}
}

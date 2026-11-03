package redact

import (
	"math/rand"
	"strings"
	"testing"
	"time"
)

// A rule that keeps a leading part of its match and scans the rest of the line
// again must not cost more than one pass over the line. The longest line is
// DefaultMaxLine (1 MiB). The cost used to grow with the square of the line
// length (4.5 minutes for 1 MiB); it is now below 1 s, and the bound is generous.
func TestRepeatedSkippedTextIsLinear(t *testing.T) {
	r := builtinOnly(t)
	const size = 1 << 20
	for name, unit := range map[string]string{
		"openssl":       "X509_check_private_key:key values mismatch ",
		"failmount":     `MountVolume.SetUp failed for volume "db-secret" : secret "db-secret" not found `,
		"failed_volume": `failed for volume "db-token" : reason `,
	} {
		line := strings.Repeat(unit, size/len(unit)+1)[:size]
		done := make(chan string, 1)
		start := time.Now()
		go func() { done <- r.Line(line) }()
		select {
		case got := <-done:
			t.Logf("%s: %d bytes in %v", name, len(line), time.Since(start))
			_ = got
		case <-time.After(linearScanBound):
			t.Errorf("%s: %d bytes not redacted within %v", name, len(line), linearScanBound)
		}
	}
}

// The repeated text stays readable and a credential after it is redacted, on
// a long line as on a short one.
func TestRepeatedSkippedTextKeepsResult(t *testing.T) {
	r := builtinOnly(t)
	unit := "error:0B080074:x509 certificate routines:X509_check_private_key:key values mismatch "
	line := strings.Repeat(unit, 500) + "token=LEAKR7"
	got := r.Line(line)
	if strings.Contains(got, "LEAKR7") {
		t.Errorf("leaks: %q", got[len(got)-80:])
	}
	if want := strings.Repeat(unit, 500) + "[REDACTED:credential]"; got != want {
		t.Errorf("repeated text changed")
	}
	mount := `Warning  FailedMount  1m  kubelet  MountVolume.SetUp failed for volume "db-secret" : secret "db-secret" not found `
	line = strings.Repeat(mount, 500)
	if got := r.Line(line); got != line {
		t.Errorf("repeated FailedMount text changed")
	}
}

// curl -u value is one shell word: quotes may appear anywhere in it.
func TestCurlUserValueIsOneShellWord(t *testing.T) {
	r := builtinOnly(t)
	checkSecretCases(t, r, []secretCase{
		{`curl -u '':LEAKR71 http://h`, "LEAKR71"},
		{`curl -u"":LEAKR72 http://h`, "LEAKR72"},
		{`curl --user "":LEAKR73 http://h`, "LEAKR73"},
		{`curl -u "a":LEAKR74 http://h`, "LEAKR74"},
		{`curl -u 'a':LEAKR75 http://h`, "LEAKR75"},
		{`curl -u a:"p LEAKR76" http://h`, "LEAKR76"},
		{`curl -u a:'p LEAKR77' http://h`, "LEAKR77"},
		{`curl -u "a b":'p LEAKR78' http://h`, "LEAKR78"},
		{`curl --user='a':"p LEAKR79" http://h`, "LEAKR79"},
		{`curl --proxy-user "p":LEAKR80 http://h`, "LEAKR80"},
		{`curl -u a:b"c LEAKR81"d http://h`, "LEAKR81"},
	})
	for line, want := range map[string]string{
		`curl -u '':LEAKR71 http://h`:          `curl -u [REDACTED:cli_password] http://h`,
		`curl -u a:"p LEAKR76" http://h`:       `curl -u [REDACTED:cli_password] http://h`,
		`curl -u a:'p LEAKR77' -s http://h`:    `curl -u [REDACTED:cli_password] -s http://h`,
		`curl --user "a":"p LEAKR79" http://h`: `curl --user [REDACTED:cli_password] http://h`,
	} {
		if got := r.Line(line); got != want {
			t.Errorf("%q => %q, want %q", line, got, want)
		}
	}
	checkSecretCases(t, r, []secretCase{
		{"docker exec -u 1000:1000 app curl http://h", ""},
		{"curl -u admin http://h", ""},
		{`curl -u "admin" http://h`, ""},
		{`curl -u '' http://h:80/x`, ""},
		{"curl -XPUT http://h:80/x", ""},
	})
}

// applyRuleReference is the first version of the skip handling: it scans the
// text after a skipped part again with the whole expression. It is slow on long
// lines and only used to check that the single-pass scan gives the same result.
func applyRuleReference(line string, rule compiledRule) string {
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
		if rule.keep != nil && rule.keep(line[m[0]:m[1]]) {
			continue
		}
		if n := rule.skip(line[m[0]:m[1]]); n > 0 {
			out.WriteString(line[cursor : m[0]+n])
			out.WriteString(applyRuleReference(line[m[0]+n:], rule))
			return out.String()
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

func TestSinglePassScanMatchesReference(t *testing.T) {
	r := builtinOnly(t)
	var rules []compiledRule
	for _, rule := range r.rules {
		if rule.skip != nil {
			rules = append(rules, rule)
		}
	}
	if len(rules) != 2 {
		t.Fatalf("rules with skip: %d", len(rules))
	}
	words := []string{
		"X509_check_private_key:key values mismatch", "x509_check_private_key:", "key values mismatch", "mismatch", "mismatching", "routines:",
		"failed for volume ", "failed  for\tvolume ", "volume ", "Volume ", `"db-secret"`, `'db-secret'`, `\"db-secret\"`, `"api_key"`, `"password"`, `'token'`,
		"secret_key:", "secret:", "password:", "token=", "-token:", "private_key", "passphrase", "api_key", "key", "pwd",
		" : ", ":", ": ", " ", "  ", "\t", ",", "{", "[", "]", "-", "- ", `"`, `'`, `\`, `\"`, ";", "=", "\n",
		"LEAK", "value", `"quoted value"`, `'quoted value'`, `"open`, "<set to the key 'k' in secret 's'>  Optional: false", "<set to the key 'k' of config map 'm'>",
		"not found", "reason", "é", "ſ",
	}
	rng := rand.New(rand.NewSource(11))
	for i := 0; i < 60000; i++ {
		var b strings.Builder
		for n := rng.Intn(10) + 1; n > 0; n-- {
			b.WriteString(words[rng.Intn(len(words))])
			if rng.Intn(3) == 0 {
				b.WriteByte(' ')
			}
		}
		line := b.String()
		for _, rule := range rules {
			if got, want := applyRule(line, rule), applyRuleReference(line, rule); got != want {
				t.Fatalf("%q\n got  %q\n want %q", line, got, want)
			}
		}
	}
}

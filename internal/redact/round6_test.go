package redact

import (
	"strings"
	"testing"
)

// N3: the OpenSSL exception covers the message text only. A value after the
// function name, and any credential later on the same line, is still scanned.
func TestOpenSSLExceptionCoversMessageTextOnly(t *testing.T) {
	r := builtinOnly(t)
	checkSecretCases(t, r, []secretCase{
		{"X509_check_private_key: LEAKN88", "LEAKN88"},
		{"error:0B080074:x509 certificate routines:X509_check_private_key:key values mismatch; secret_key: LEAKN87", "LEAKN87"},
		{"error:0B080074:x509 certificate routines:X509_check_private_key:key values mismatch token=LEAKN85", "LEAKN85"},
		{"X509_check_private_key:key values mismatchLEAKN84", "LEAKN84"},
		{"X509_check_private_key:LEAKN83", "LEAKN83"},
		{"X509_check_private_key:key values mismatching LEAKN82", "LEAKN82"},
	})
	for _, line := range []string{
		"error:0B080074:x509 certificate routines:X509_check_private_key:key values mismatch",
		"[emerg] SSL_CTX_use_PrivateKey(\"/etc/ssl/x.key\") failed (SSL: error:0B080074:x509 certificate routines:X509_check_private_key:key values mismatch)",
	} {
		if got := r.Line(line); got != line {
			t.Errorf("changed %q => %q", line, got)
		}
	}
}

// N3: a value after a quoted volume name is redacted. The kubelet FailedMount
// event ("failed for volume ... : reason") stays readable, and a credential
// later on the event line is still redacted.
func TestQuotedVolumeNameKeyAndFailedMountEvent(t *testing.T) {
	r := builtinOnly(t)
	checkSecretCases(t, r, []secretCase{
		{`volume "db-secret" : LEAKN89`, "LEAKN89"},
		{`volume 'db-secret' : LEAKN90`, "LEAKN90"},
		{`msg=volume \"db-secret\" : LEAKN91`, "LEAKN91"},
		{`Volume "api-token": LEAKN92`, "LEAKN92"},
		{`Warning  FailedMount  1m  kubelet  MountVolume.SetUp failed for volume "db-secret" : secret "db-secret" not found; secret_key: LEAKN93`, "LEAKN93"},
	})
	for _, line := range []string{
		`Warning  FailedMount  1m  kubelet  MountVolume.SetUp failed for volume "db-secret" : secret "db-secret" not found`,
		`Warning  FailedMount  1m  kubelet  MountVolume.SetUp failed for volume 'db-secret' : secret 'db-secret' not found`,
		`Warning  FailedMount  1m  kubelet  MountVolume.SetUp failed for volume "default-token-x8k2f" : failed to sync secret cache: timed out waiting for the condition`,
		`E1022 10:00:00 1 nestedpendingoperations.go] "err" err="MountVolume.SetUp failed for volume \"db-secret\" : secret \"db-secret\" not found"`,
		`Warning  FailedMount  1m  kubelet  AttachVolume.Attach failed for volume "api-token" : rpc error: code = Internal`,
	} {
		if got := r.Line(line); got != line {
			t.Errorf("changed %q => %q", line, got)
		}
	}
}

// N4: a quoted key as a YAML sequence item.
func TestQuotedKeyAsYAMLSequenceItem(t *testing.T) {
	r := builtinOnly(t)
	checkSecretCases(t, r, []secretCase{
		{`  - "api_key": "LEAKN84"`, "LEAKN84"},
		{`- "password": "LEAKN85"`, "LEAKN85"},
		{`- 'token': 'LEAKN86'`, "LEAKN86"},
		{`    -   "secret": LEAKN87`, "LEAKN87"},
		{`- - "password": "LEAKN88"`, "LEAKN88"},
	})
	for _, line := range []string{`  - "name": "web"`, `- "port": 8080`, `- "tokens_per_second": 5`} {
		if got := r.Line(line); got != line {
			t.Errorf("changed %q => %q", line, got)
		}
	}
}

// N7: curl -u with an empty user name.
func TestCurlEmptyUserName(t *testing.T) {
	r := builtinOnly(t)
	checkSecretCases(t, r, []secretCase{
		{"curl -u:LEAKN10 http://h", "LEAKN10"},
		{"curl -u :LEAKN11 http://h", "LEAKN11"},
		{"curl -sS -u:LEAKN12 http://h", "LEAKN12"},
		{"curl --user :LEAKN13 http://h", "LEAKN13"},
		{"curl --user=:LEAKN14 http://h", "LEAKN14"},
		{`curl -u ":LEAKN15" http://h`, "LEAKN15"},
		{"curl -fsSu:LEAKN16 http://h", "LEAKN16"},
	})
}

// N9: the option words pwd and passphrase.
func TestOptionWordsPwdAndPassphrase(t *testing.T) {
	r := builtinOnly(t)
	checkSecretCases(t, r, []secretCase{
		{"app --pwd Hunter2", "Hunter2"},
		{"app --pwd=Hunter2", "Hunter2"},
		{"app --db-pwd Hunter2", "Hunter2"},
		{`app ["--pwd","Hunter2"]`, "Hunter2"},
		{"app --passphrase Hunter2", "Hunter2"},
		{"app --passphrase=Hunter2", "Hunter2"},
		{"gpg --batch --passphrase Hunter2", "Hunter2"},
		{`app ["--passphrase","Hunter2"]`, "Hunter2"},
	})
}

// N8: the words inside a marker such as [REDACTED:url_credentials] must not
// start the credential rules again; a credential after a replaced text is
// still found because the filter uses the text before the replacement.
func TestCredentialAfterReplacedTextIsRedacted(t *testing.T) {
	r := builtinOnly(t)
	checkSecretCases(t, r, []secretCase{
		{"dsn: root:pw1@tcp(h:3306)/db password=LEAKN80", "LEAKN80"},
		{"url: a://b:pw2@d token: LEAKN81", "LEAKN81"},
		{"Server a://b:pw3@d; secret_key: LEAKN82", "LEAKN82"},
	})
	got := r.Line("a:b@tcp( a:b@tcp( a://b:c@d x_token=LEAKN83")
	if got != "[REDACTED:url_credentials]tcp( [REDACTED:url_credentials]tcp( [REDACTED:url_credentials]d [REDACTED:credential]" {
		t.Errorf("got %q", got)
	}
}

// A custom rule with BeforeBuiltin runs before the builtin rules, in the order
// of the configuration. Without it the rule runs after them.
func TestCustomRuleBeforeBuiltin(t *testing.T) {
	quoted := Rule{Name: "quoted", Regex: `'[^']*'`}
	line := `h = 'Authorization: Bearer abcd' AND x = 'LEAKSEP'`
	after, err := New(&Config{Custom: []Rule{quoted}})
	if err != nil {
		t.Fatal(err)
	}
	if got := after.Line(line); !strings.Contains(got, "LEAKSEP") {
		t.Fatalf("control: the builtin bearer rule is expected to consume the closing quote first, got %q", got)
	}
	quoted.BeforeBuiltin = true
	before, err := New(&Config{Custom: []Rule{quoted, {Name: "digits", Regex: `[0-9]+`, BeforeBuiltin: true}, {Name: "last", Regex: `AND`}}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := before.Line(line), "h = [REDACTED:quoted] [REDACTED:last] x = [REDACTED:quoted]"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// Only the custom rules move; the builtin rules still run on the rest.
	if got := before.Line("token=Hunter2 'a'"); strings.Contains(got, "Hunter2") {
		t.Errorf("builtin rule did not run: %q", got)
	}
	none, err := New(&Config{Builtin: []string{}, Custom: []Rule{quoted}})
	if err != nil {
		t.Fatal(err)
	}
	if got := none.Line("'a' 'b'"); got != "[REDACTED:quoted] [REDACTED:quoted]" {
		t.Errorf("without builtins: %q", got)
	}
}

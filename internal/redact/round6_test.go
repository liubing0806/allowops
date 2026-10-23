package redact

import "testing"

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

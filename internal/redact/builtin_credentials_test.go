package redact

import (
	"strings"
	"testing"
)

type secretCase struct {
	line   string
	secret string // must not survive; empty when the line must stay unchanged
}

func checkSecretCases(t *testing.T, r *Redactor, cases []secretCase) {
	t.Helper()
	for _, tc := range cases {
		got := r.Line(tc.line)
		if tc.secret == "" {
			if got != tc.line {
				t.Errorf("changed %q => %q", tc.line, got)
			}
			continue
		}
		if strings.Contains(got, tc.secret) {
			t.Errorf("leaks %q: %q => %q", tc.secret, tc.line, got)
		}
		if !strings.Contains(got, "[REDACTED:") {
			t.Errorf("no marker: %q => %q", tc.line, got)
		}
	}
}

func builtinOnly(t *testing.T) *Redactor {
	t.Helper()
	r, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// redaction/F1: URL credentials with an empty user name, a password that
// contains '@', and Oracle thin URLs.
func TestBuiltinURLCredentialForms(t *testing.T) {
	r := builtinOnly(t)
	checkSecretCases(t, r, []secretCase{
		{"spring.redis.url=redis://:RedisPw123@10.0.0.5:6379/0", "RedisPw123"},
		{"REDIS_URL: redis://:RedisUrlPw@redis:6379/0", "RedisUrlPw"},
		{"redis conn redis://:LogRedisPw@10.0.0.5:6379", "LogRedisPw"},
		{"spring.datasource.url2=jdbc:mysql://root:p@ss@db:3306/x", "ss@db"},
		{"spring.datasource.url2=jdbc:mysql://root:p@ss@db:3306/x", "p@ss"},
		{"spring.datasource.url=jdbc:oracle:thin:scott/OraPw456@10.0.0.6:1521:ORCL", "OraPw456"},
		{"url=jdbc:oracle:thin:scott/Ora@Pw9@10.0.0.6:1521/svc", "Pw9"},
		{"url=jdbc:oracle:thin:scott/OraPw457@//10.0.0.6:1521/svc", "OraPw457"},
		{`{"url":"redis://:JsonPw1@h:6379","mail":"a@b.com"}`, "JsonPw1"},
		{"postgres://app:PgPw@pg:5432/app", "PgPw"},
	})
	for _, tc := range []struct{ input, want string }{
		{"redis://:RedisPw123@10.0.0.5:6379/0", "[REDACTED:url_credentials]10.0.0.5:6379/0"},
		{"jdbc:mysql://root:p@ss@db:3306/x", "jdbc:[REDACTED:url_credentials]db:3306/x"},
		{"jdbc:oracle:thin:scott/OraPw456@10.0.0.6:1521:ORCL", "[REDACTED:url_credentials]10.0.0.6:1521:ORCL"},
		{`{"url":"redis://:JsonPw1@h:6379","mail":"a@b.com"}`, `{"url":"[REDACTED:url_credentials]h:6379","mail":"a@b.com"}`},
	} {
		if got := r.Line(tc.input); got != tc.want {
			t.Errorf("%q => %q, want %q", tc.input, got, tc.want)
		}
	}
	checkSecretCases(t, r, []secretCase{
		{"redis://10.0.0.5:6379/0", ""},
		{"http://host:8080/path@x", ""},
		{"http://[::1]:8080/", ""},
		{"ssh://git@host:22/repo", ""},
		{"jdbc:oracle:thin:@//host:1521/svc", ""},
		{"jdbc:oracle:thin:@host:1521:ORCL", ""},
		{"jdbc:mysql://db:3306/x?useSSL=false", ""},
		{"listening on http://0.0.0.0:8080 contact ops@example.com", ""},
	})
}

// redaction/F3: Basic authorization, API key headers and htpasswd hashes.
func TestBuiltinHeadersAndHtpasswdHashes(t *testing.T) {
	r := builtinOnly(t)
	checkSecretCases(t, r, []secretCase{
		{`proxy_set_header Authorization "Basic dXNlcjpQYXNzMTIz";`, "dXNlcjpQYXNzMTIz"},
		{"Authorization: Basic dXNlcjpQYXNzMTIz", "dXNlcjpQYXNzMTIz"},
		{`curl -H "Authorization: Basic dXNlcjpQYXNzMTIz" http://127.0.0.1/`, "dXNlcjpQYXNzMTIz"},
		{`{"Authorization": "Basic dXNlcjpQYXNzMTIz"}`, "dXNlcjpQYXNzMTIz"},
		{"Authorization: Digest username=\"u\", response=\"abcdef0123456789\"", "abcdef0123456789"},
		{"proxy_set_header X-Api-Key abc123secretvalue;", "abc123secretvalue"},
		{"add_header X-Auth-Token tok123456;", "tok123456"},
		{"X-Api-Key: abc123secretvalue", "abc123secretvalue"},
		{"x-auth-token: tok123456", "tok123456"},
		{`curl -H 'X-Api-Key: kk9988776655' http://127.0.0.1/`, "kk9988776655"},
		{"admin:$apr1$abcd1234$AbCdEfGhIjKlMnOpQrStU.", "AbCdEfGhIjKlMnOpQrStU"},
		{"carol:$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234", "abcdefghijklmnopqrstuu"},
		{"bob:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=", "W6ph5Mm5Pz8GgiULbPgzG37mj9g"},
		{"root:$6$saltsalt$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:19000:0:99999:7:::", "abcdefghijklmnopqrstuvwxyz"},
	})
	for _, tc := range []struct{ input, want string }{
		{"Authorization: Basic dXNlcjpQYXNzMTIz", "[REDACTED:auth_header]"},
		{`proxy_set_header Authorization "Basic dXNlcjpQYXNzMTIz";`, "[REDACTED:auth_header];"},
		{"proxy_set_header X-Api-Key abc123secretvalue;", "[REDACTED:api_key_header];"},
		{"admin:$apr1$abcd1234$AbCdEfGhIjKlMnOpQrStU.", "admin:[REDACTED:htpasswd_hash]"},
		{"Authorization: Bearer opaque-token", "[REDACTED:bearer]"},
	} {
		if got := r.Line(tc.input); got != tc.want {
			t.Errorf("%q => %q, want %q", tc.input, got, tc.want)
		}
	}
	checkSecretCases(t, r, []secretCase{
		{"X-Request-Id: 12345", ""},
		{"X-Forwarded-For: 10.0.0.1", ""},
		{"proxy_set_header Host $host;", ""},
		{"add_header Cache-Control no-cache;", ""},
		{"Content-Type: application/json", ""},
		{"price is $1 or $5 today", ""},
	})
}

// redaction/F5: colon-form credentials such as the Environment section of
// kubectl describe pod.
func TestBuiltinColonFormCredentials(t *testing.T) {
	r := builtinOnly(t)
	describe := []secretCase{
		{"      SPRING_DATASOURCE_PASSWORD:  Hunter2Prod", "Hunter2Prod"},
		{"      MYSQL_ROOT_PASSWORD:         RootPw1", "RootPw1"},
		{"      JWT_SECRET:                  jwtsecretvalue", "jwtsecretvalue"},
		{"      API_TOKEN:                   tok_live_abc123", "tok_live_abc123"},
		{"      AWS_SECRET_ACCESS_KEY:       wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI"},
		{"      DB_PASSWORD:  v@lue with spaces", "with spaces"},
		{"password: v1", "v1"},
		{"  password: 'two words'", "two words"},
		{`  password: "quoted \" pw"`, "pw"},
		{"client_secret: ymlsecret1", "ymlsecret1"},
		{"Password : spaced1", "spaced1"},
		{`{"password":"jsonpw3","user":"bob"}`, "jsonpw3"},
		{`"db_password": "jsonpw4",`, "jsonpw4"},
		{`\"password\":\"escapedpw5\"`, "escapedpw5"},
		{"Using generated security password: 5f2a-b1c3-d4e5", "5f2a-b1c3-d4e5"},
		{"apiKey: ak123456", "ak123456"},
		{"accessToken: at123456", "at123456"},
		{"db_pwd: dbpw1", "dbpw1"},
		{"pwd: barepw1", "barepw1"},
		{"      PGPASSWORD=pgpw1 psql -h db", "pgpw1"},
		{`"DB_PASSWORD=inspectpw2",`, "inspectpw2"},
		{"export AWS_SECRET_ACCESS_KEY=envsecret3", "envsecret3"},
		{"https://example.com/cb?access_token=qtok4&state=1", "qtok4"},
		{"*/5 * * * * DB_PASSWORD=cronpw5 /opt/app/run.sh", "cronpw5"},
		{"client_secret = 'with space'", "with space"},
	}
	checkSecretCases(t, r, describe)
	if got := r.Line("      DB_PASSWORD:  Hunter2"); got != "      [REDACTED:credential]" {
		t.Errorf("describe line => %q", got)
	}
	if got := r.Line(`{"password":"jsonpw3","user":"bob"}`); !strings.Contains(got, `"user":"bob"`) {
		t.Errorf("quoted value must not consume following fields: %q", got)
	}
	checkSecretCases(t, r, []secretCase{
		{"    Environment:", ""},
		{"      DB_PASSWORD:  <set to the key 'password' in secret 'db-secret'>  Optional: false", ""},
		{"      CFG_TOKEN:    <set to the key 'token' of config map 'app-cfg'>  Optional: true", ""},
		{"    SecretName:  db-secret", ""},
		{"    TokenExpirationSeconds:  3607", ""},
		{"    Type:  Secret (a volume populated by a Secret)", ""},
		{"Image Pull Secrets:  <none>", ""},
		{"PWD=/opt/app", ""},
		{"OLDPWD=/home/app", ""},
		{"token_count: 5", ""},
		{"max_tokens: 100", ""},
		{"tokenizer: bpe", ""},
		{"key: value", ""},
		{"primary_key: id", ""},
		{"keys: 5", ""},
		{"Password:", ""},
		{"password is unset", ""},
		{"app.name=demo", ""},
	})
	// A secretKeyRef-style value that also carries a real value must still be hidden.
	checkSecretCases(t, r, []secretCase{
		{"      DB_PASSWORD:  <set to the key 'password' in secret 'db'>  Optional: false hunter9", "hunter9"},
	})
}

// Normal log lines that contain a credential keyword followed by a colon.
// These are redacted on purpose; the lines document the accepted
// over-redaction (docs/action-catalog-requirements.md section 2).
func TestBuiltinColonFormOverRedactionIsKnown(t *testing.T) {
	r := builtinOnly(t)
	for _, tc := range []struct{ input, want string }{
		{"INFO token: 5 refreshed", "INFO [REDACTED:credential]"},
		{"INFO password: changed successfully", "INFO [REDACTED:credential]"},
		{"ERROR failed to read secret: not found", "ERROR failed to read [REDACTED:credential]"},
	} {
		if got := r.Line(tc.input); got != tc.want {
			t.Errorf("%q => %q, want %q", tc.input, got, tc.want)
		}
	}
}

// redaction/F6: command-line passwords.
func TestBuiltinCommandLinePasswords(t *testing.T) {
	r := builtinOnly(t)
	checkSecretCases(t, r, []secretCase{
		{"*/5 * * * * curl -s -u admin:CurlPw1 http://127.0.0.1:8080/health", "CurlPw1"},
		{"curl --user admin:CurlPw2 http://127.0.0.1/", "CurlPw2"},
		{"curl --user=admin:CurlPw3 http://127.0.0.1/", "CurlPw3"},
		{`curl -sSu "admin:Curl Pw4" http://127.0.0.1/`, "Pw4"},
		{"curl --proxy-user pu:CurlPw5 -x http://proxy:3128 http://127.0.0.1/", "CurlPw5"},
		{"0 3 * * * redis-cli -h 10.0.0.5 -a RedisCliPw2 bgsave", "RedisCliPw2"},
		{"0 3 * * * /usr/bin/redis-cli -a 'Redis Cli Pw6' bgsave", "Cli Pw6"},
		{"valkey-cli -a ValkeyPw7 ping", "ValkeyPw7"},
		{"redis-cli --user app --pass RedisPassOpt8 ping", "RedisPassOpt8"},
		{"0 9 * * * redis-server --requirepass SrvPw7", "SrvPw7"},
		{"redis-server --port 6380 --requirepass=SrvPw9 --masterauth MasterPw10", "SrvPw9"},
		{"redis-server --masterauth MasterPw10", "MasterPw10"},
		{"0 7 * * * sshpass -p 'SshPw5' scp a b", "SshPw5"},
		{"sshpass -p SshPw11 ssh app@host uptime", "SshPw11"},
		{`sshpass -p "Ssh Pw12" ssh app@host`, "Pw12"},
		{"tool --password ToolPw13 --verbose", "ToolPw13"},
		{"tool --db-password ToolPw14", "ToolPw14"},
		{"kubectl get pods --token TokPw15", "TokPw15"},
		{"mysqldump -uroot -pDumpPw3 db", "DumpPw3"},
	})
	if got := r.Line("0 9 * * * redis-server --requirepass SrvPw7"); got != "0 9 * * * redis-server --requirepass [REDACTED:cli_password]" {
		t.Errorf("requirepass => %q", got)
	}
	checkSecretCases(t, r, []secretCase{
		{"mysql -u root -h localhost", ""},
		{"docker exec -u 1000:1000 app sh", ""},
		{"docker run --user 1000:1000 app", ""},
		{"crontab -u app -l", ""},
		{"ps -a", ""},
		{"docker ps -a", ""},
		{"redis-cli -h 10.0.0.5 ping", ""},
		{"curl -s http://127.0.0.1:8080/health", ""},
		{"curl -u admin http://127.0.0.1/", ""},
		{"curl --user-agent probe/1.0 http://127.0.0.1/", ""},
		{"psql --no-password mydb", ""},
		{"ansible-playbook --ask-pass site.yml", ""},
		{"docker login --password-stdin", ""},
		{"tool --token-file /opt/app/token", ""},
		{"ssh -p 2222 app@host", ""},
		{"sshpass -e ssh app@host", ""},
	})
}

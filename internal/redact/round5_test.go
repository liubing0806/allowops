package redact

import (
	"fmt"
	"testing"
)

// exact asserts the full output, for lines where the surrounding text matters.
func checkExact(t *testing.T, r *Redactor, cases [][2]string) {
	t.Helper()
	for _, tc := range cases {
		if got := r.Line(tc[0]); got != tc[1] {
			t.Errorf("%q => %q, want %q", tc[0], got, tc[1])
		}
	}
}

// R4-RED-1, R4-RED-6, GC-3: an unquoted value of a credential key with '='
// runs to the end of the line, like the colon form. A password may hold
// spaces or ';'. Quoted values accept backslash escapes (double quotes) and
// doubled quotes (single quotes).
func TestEqualsFormValueRunsToEndOfLine(t *testing.T) {
	r := builtinOnly(t)
	checkSecretCases(t, r, []secretCase{
		{"DB_PASSWORD=ab;LEAKME", "LEAKME"},
		{"REDIS_PASSWORD=x;y;zLEAK", "zLEAK"},
		{"MAIL_PASSWORD=ab LEAKME", "LEAKME"},
		{"JWT_SECRET=ab LEAKME", "LEAKME"},
		{"ACCESS_TOKEN=a b LEAKME", "LEAKME"},
		{"SMTP_TOKEN=q;LEAKME", "LEAKME"},
		{"APP_SECRET=ab LEAKME", "LEAKME"},
		{"DB_PASSWORD=correct Hunter2 battery", "Hunter2"},
		{"app.password=correct horse Hunter2", "Hunter2"},
		{"password=hello world LEAKME", "LEAKME"},
		{"secret=ab;LEAKME", "LEAKME"},
		{"token=ab LEAKME", "LEAKME"},
		{"MYSQL_PWD=ab LEAKME", "LEAKME"},
		{"REDISCLI_AUTH=ab LEAKME", "LEAKME"},
		{"MYSQL_PWD=ab;LEAKME", "LEAKME"},
		{`DB_PASSWORD="ab\"Hunter2"`, "Hunter2"},
		{`password="ab\"Hunter2"`, "Hunter2"},
		{`password="a\"Hunter2 c"`, "Hunter2"},
		{`DB_PASSWORD="ab\\\"Hunter2 c"`, "Hunter2"},
		{`DB_PASSWORD="unterminated Hunter2`, "Hunter2"},
		{"password='it''s Hunter2'", "Hunter2"},
		{"DB_PASSWORD='it''s Hunter2'", "Hunter2"},
		{"password: 'it''s Hunter2'", "Hunter2"},
		{"MYSQL_PWD='it''s Hunter2'", "Hunter2"},
		{`--password 'it'\''s Hunter2'`, "Hunter2"},
		{`--password "it\"s Hunter2"`, "Hunter2"},
	})
	checkExact(t, r, [][2]string{
		{"DB_PASSWORD=ab;LEAKME", "[REDACTED:credential]"},
		{"password=hello world LEAKME", "[REDACTED:credential]"},
		{`password="abc def" next=1`, "[REDACTED:credential] next=1"},
		{"DB_PASSWORD='ab''cd' keep=1", "[REDACTED:credential] keep=1"},
		{`password: "a\"b c" tail`, "[REDACTED:credential] tail"},
		{"MYSQL_PWD=ab LEAKME", "[REDACTED:mysql_pwd]"},
		{"REDISCLI_AUTH=ab LEAKME", "[REDACTED:rediscli_auth]"},
		{"password=hello secret='two words' token=abc", "[REDACTED:credential]"},
		{`--password 'it'\''s Hunter2' --verbose`, "--password [REDACTED:cli_password] --verbose"},
	})
}

// GC-1: a quote inside a URL password is redacted again. A URL inside a JSON
// string still ends at the closing quote.
func TestURLPasswordWithQuote(t *testing.T) {
	r := builtinOnly(t)
	checkSecretCases(t, r, []secretCase{
		{"postgres://u:pa'Hunter2@h/db", "Hunter2"},
		{`postgres://u:pa"Hunter2@h/db`, "Hunter2"},
		{`mysql://root:x'y"Hunter2@10.0.0.1:3306/app`, "Hunter2"},
		{"url=postgres://u:pa'Hunter2@h/db", "Hunter2"},
		{`{"url":"postgres://u:pa'Hunter2@h/db","mail":"a@b.com"}`, "Hunter2"},
		{`{'url':'postgres://u:pa"Hunter2@h/db','mail':'a@b.com'}`, "Hunter2"},
		{`\"url\":\"postgres://u:pa'Hunter2@h/db\"`, "Hunter2"},
	})
	checkExact(t, r, [][2]string{
		{`{"url":"redis://:pw@h","mail":"a@b.com"}`, `{"url":"[REDACTED:url_credentials]h","mail":"a@b.com"}`},
		{`{'url':'redis://:pw@h','mail':'a@b.com'}`, `{'url':'[REDACTED:url_credentials]h','mail':'a@b.com'}`},
		{"postgres://u:pa'x@h/db", "[REDACTED:url_credentials]h/db"},
		{`{"a":"b://c","d":"e@f"}`, `{"a":"b://c","d":"e@f"}`},
		{"it's http://host:8080/x and 'a@b'", "it's http://host:8080/x and 'a@b'"},
	})
}

// R4-RED-2, R4-RED-5, GC-2: curl -uUSER:PASS without a separator, several -u
// options, and long option names with '_', '.', secret-key, private-key.
func TestCommandLineOptionForms(t *testing.T) {
	r := builtinOnly(t)
	checkSecretCases(t, r, []secretCase{
		{"curl -uadmin:Hunter2 http://h", "Hunter2"},
		{"curl -sS -uadmin:Hunter2 http://h", "Hunter2"},
		{"*/5 * * * * curl -uadmin:Hunter2 http://h/api", "Hunter2"},
		{"curl -sSuadmin:Hunter2 http://h", "Hunter2"},
		{`curl -u"admin:Hunter2 x" http://h`, "Hunter2"},
		{"curl -u a:Hunter1 -u c:Hunter2 http://h", "Hunter1"},
		{"curl -u a:Hunter1 -u c:Hunter2 http://h", "Hunter2"},
		{"curl -uadmin:Hunter1 --proxy-user pu:Hunter2 http://h", "Hunter2"},
		{"redis-cli -aHunter2 ping", "Hunter2"},
		{"redis-cli -h 10.0.0.5 -aHunter2 ping", "Hunter2"},
		{"/opt/bin/backup --secret-key Hunter2", "Hunter2"},
		{"mc alias set x --access-key AK1 --secret-key Hunter2", "Hunter2"},
		{"mc alias set x --access-key AK1 --secret-key Hunter2", "AK1"},
		{"app --client_secret Hunter2", "Hunter2"},
		{"app --private-key Hunter2", "Hunter2"},
		{"app --admin.password Hunter2", "Hunter2"},
		{"java -jar a.jar --server.ssl.key-store-password Hunter2", "Hunter2"},
		{"tool --api_key Hunter2", "Hunter2"},
		{"tool --api.key Hunter2", "Hunter2"},
		{"tool --encryption-key Hunter2", "Hunter2"},
		{"tool --auth Hunter2", "Hunter2"},
		{"tool --basic-auth Hunter2", "Hunter2"},
		{"tool --aws-secret-access-key Hunter2", "Hunter2"},
		{"tool --secret_key=Hunter2", "Hunter2"},
		{`"Cmd":["tool","--secret-key","Hunter2"]`, "Hunter2"},
		{`"Cmd":["tool","--client_secret","Hunter2"]`, "Hunter2"},
		{`"Cmd":["tool","--admin.password","Hunter2"]`, "Hunter2"},
	})
	checkExact(t, r, [][2]string{
		{"curl -uadmin:Hunter2 http://h", "curl -u[REDACTED:cli_password] http://h"},
		{"curl -u a:b1 -u c:d2 http://h", "curl -u [REDACTED:cli_password] -u [REDACTED:cli_password] http://h"},
		{"redis-cli -aHunter2 ping", "redis-cli -a[REDACTED:cli_password] ping"},
		{"app --secret-key Hunter2 --verbose", "app --secret-key [REDACTED:cli_password] --verbose"},
	})
	checkSecretCases(t, r, []secretCase{
		{"docker exec -u 1000:1000 app curl http://h", ""},
		{"curl -XPUT http://h:80/x", ""},
		{"curl -sS --url http://h:80/x", ""},
		{"curl -u admin http://h:80/x", ""},
		{"curl -sSL -H 'Accept: x' http://u.example:80/", ""},
		{"curl -sS --user-agent probe/1.0 http://h:80/", ""},
		{"tool --secret-name db", ""},
		{"tool --key-file /opt/app/key", ""},
		{"mongod --auth --port 27017", ""},
		{"tool --no-secret-key", ""},
		{"redis-cli --askpass ping", ""},
		{"redis-cli -h 10.0.0.5 -x ping", ""},
		{`"Cmd":["tool","--secret-name","db"]`, ""},
	})
}

// R4-RED-3, GC-4: pass bound by a separator, a camelCase boundary or the key
// start. bypass, compass and passed stay readable.
func TestPassKeys(t *testing.T) {
	r := builtinOnly(t)
	checkSecretCases(t, r, []secretCase{
		{"DB_PASS=Hunter2", "Hunter2"},
		{"MYSQL_PASS=Hunter2", "Hunter2"},
		{"MYSQL_ROOT_PASS=Hunter2", "Hunter2"},
		{"redis.pass=Hunter2", "Hunter2"},
		{"db.pass=Hunter2", "Hunter2"},
		{"spring.redis.pass: Hunter2", "Hunter2"},
		{"SMTP_PASS: Hunter2", "Hunter2"},
		{"    DB_PASS:  Hunter2", "Hunter2"},
		{"    ES_PASS:  Hunter2", "Hunter2"},
		{"pass: Hunter2", "Hunter2"},
		{"pass=Hunter2", "Hunter2"},
		{"keystorePass=Hunter2", "Hunter2"},
		{"db-pass=Hunter2", "Hunter2"},
		{"*/5 * * * * DB_PASS=Hunter2 /opt/app/run.sh", "Hunter2"},
	})
	checkExact(t, r, [][2]string{
		{"    DB_PASS:  Hunter2", "    [REDACTED:credential]"},
		{"DB_PASS=Hunter2", "[REDACTED:credential]"},
	})
	checkSecretCases(t, r, []secretCase{
		{"bypass=1", ""},
		{"bypass: true", ""},
		{"compass: north", ""},
		{"compass=north", ""},
		{"passed: 5", ""},
		{"passed=5", ""},
		{"passport=x1", ""},
		{"PASSENGER: 3", ""},
		{"Bypass: yes", ""},
		{"overpass: x", ""},
	})
}

// R4-RED-4: key names that end in key without the listed separator forms.
func TestMoreKeyNames(t *testing.T) {
	r := builtinOnly(t)
	checkSecretCases(t, r, []secretCase{
		{"SECRET_KEY_BASE=Hunter2", "Hunter2"},
		{"APP_KEY=base64:Hunter2", "Hunter2"},
		{"ENCRYPT_KEY=Hunter2", "Hunter2"},
		{"SIGN_KEY=Hunter2", "Hunter2"},
		{"SignKey=Hunter2", "Hunter2"},
		{"sign.key=Hunter2", "Hunter2"},
		{"api.key=Hunter2", "Hunter2"},
		{"jwt.secret.key: Hunter2", "Hunter2"},
		{"encryption.key=Hunter2", "Hunter2"},
		{"private.key=Hunter2", "Hunter2"},
		{"nacos.core.auth.plugin.nacos.token.secret.key=Hunter2", "Hunter2"},
		{"    SECRET_KEY_BASE:  Hunter2", "Hunter2"},
		{"    APP_KEY:          base64:Hunter2", "Hunter2"},
		{"    ENCRYPT_KEY:      Hunter2", "Hunter2"},
		{"    SIGN_KEY:         Hunter2", "Hunter2"},
		{"secret-key-base: Hunter2", "Hunter2"},
	})
	checkSecretCases(t, r, []secretCase{
		{"key=value", ""},
		{"key: value", ""},
		{"primary_key=id", ""},
		{"primary_key: id", ""},
		{"foreign_key: owner_id", ""},
		{"design_key=x1", ""},
		{"assign.key=x1", ""},
		{"webapp_key=x1", ""},
		{"monkey=banana", ""},
		{"keyboard: us", ""},
	})
}

// R4-RED-7: Go MySQL DSN without a scheme, and a token as the only userinfo.
func TestDSNAndTokenOnlyURL(t *testing.T) {
	r := builtinOnly(t)
	checkSecretCases(t, r, []secretCase{
		{"dsn: root:Hunter2@tcp(10.0.0.1:3306)/app?charset=utf8mb4", "Hunter2"},
		{"connecting to root:Hunter2@tcp(10.0.0.1:3306)/app", "Hunter2"},
		{"u:Hunter2@unix(/var/run/mysqld/mysqld.sock)/db", "Hunter2"},
		{"dsn=root:p@ss@tcp(h:3306)/x", "p@ss"},
		{"git pull https://ghp_Zq9xKabcdefghijklmn@github.com/org/repo.git", "Zq9xK"},
		{"git pull https://gho_Zq9xKabcdefghijklmn@github.com/org/repo.git", "Zq9xK"},
		{"git pull https://ghs_Zq9xKabcdefghijklmn@github.com/org/repo.git", "Zq9xK"},
		{"git pull https://github_pat_11ABCDEFG0Zq9xK_abcdefghijklmn@github.com/org/repo.git", "Zq9xK"},
		{"git pull https://glpat-" + "Zq9xKabcdefghij-klmn@gitlab.com/org/repo.git", "Zq9xK"},
	})
	checkExact(t, r, [][2]string{
		{"dsn: root:Hunter2@tcp(10.0.0.1:3306)/app", "dsn: [REDACTED:url_credentials]tcp(10.0.0.1:3306)/app"},
		{"git pull https://ghp_Zq9xKabcdefghijklmn@github.com/org/repo.git", "git pull [REDACTED:url_credentials]github.com/org/repo.git"},
	})
	checkSecretCases(t, r, []secretCase{
		{"git clone ssh://git@github.com/org/repo.git", ""},
		{"git clone ssh://git@host:22/repo", ""},
		{"git clone https://github.com/org/repo.git", ""},
		{"scp deploy@host:/srv/app/file .", ""},
		{"push ghp_Zq9xKabcdefghijklmn to server", ""},
		{"dsn: root@tcp(10.0.0.1:3306)/app", ""},
		{"listening on tcp(10.0.0.1:3306) as user@host", ""},
	})
}

// R4-RED-8: HTTP_AUTHORIZATION and every *_set_header directive.
func TestAuthorizationHeaderForms(t *testing.T) {
	r := builtinOnly(t)
	checkSecretCases(t, r, []secretCase{
		{"HTTP_AUTHORIZATION=Basic Hunter2", "Hunter2"},
		{"HTTP_AUTHORIZATION: Basic Hunter2", "Hunter2"},
		{"    HTTP_AUTHORIZATION:  Hunter2opaque", "Hunter2"},
		{`grpc_set_header Authorization "Bearer Hunter2";`, "Hunter2"},
		{`uwsgi_set_header Authorization "Basic Hunter2";`, "Hunter2"},
		{"fastcgi_param HTTP_AUTHORIZATION Basic Hunter2;", "Hunter2"},
		{"grpc_set_header X-Api-Key Hunter2;", "Hunter2"},
		{`proxy_set_header Authorization "Bearer Hunter2";`, "Hunter2"},
		{"authorization=Hunter2", "Hunter2"},
		{"Authorization=Basic Hunter2 more", "more"},
	})
	checkExact(t, r, [][2]string{
		{`grpc_set_header Authorization "Bearer Hunter2";`, "[REDACTED:auth_header];"},
		{"HTTP_AUTHORIZATION=Basic Hunter2", "[REDACTED:auth_header]"},
	})
}

// F1: a quoted key needs a matching opening quote at a place where a key can
// start, so event text and OpenSSL error codes stay readable.
func TestQuotedNameIsNotAKey(t *testing.T) {
	r := builtinOnly(t)
	for _, line := range []string{
		`Warning  FailedMount  1m  kubelet  MountVolume.SetUp failed for volume "api-secret" : secret "api-secret" not found`,
		`Warning  FailedMount  1m  kubelet  MountVolume.SetUp failed for volume "registry-token" : object "app"/"tls" not registered`,
		`Warning  FailedMount  1m  kubelet  MountVolume.SetUp failed for volume 'db-secret' : secret 'db-secret' not found`,
		`Warning  FailedMount  1m  kubelet, node1  MountVolume.SetUp failed for volume "web-config" : configmap "web" not found`,
		`volume "db-secret" :`,
		`[emerg] 1#1: SSL_CTX_use_PrivateKey("/etc/ssl/x.key") failed (SSL: error:0B080074:x509 certificate routines:X509_check_private_key:key values mismatch)`,
		`[emerg] SSL: error:0B080074:x509 certificate routines::key values mismatch`,
	} {
		if got := r.Line(line); got != line {
			t.Errorf("changed %q => %q", line, got)
		}
	}
	checkSecretCases(t, r, []secretCase{
		{`  "password": "Hunter2",`, "Hunter2"},
		{`{"password": "Hunter2"}`, "Hunter2"},
		{`{"a":1, "db-secret" : "Hunter2"}`, "Hunter2"},
		{`{"a":1,"db-secret":"Hunter2"}`, "Hunter2"},
		{`[{"token": "Hunter2"}]`, "Hunter2"},
		{`  'password': 'Hunter2'`, "Hunter2"},
		{`{'password': 'Hunter2'}`, "Hunter2"},
		{`{\"password\":\"Hunter2\"}`, "Hunter2"},
		{`body={"user":"a","password":"Hunter2"}`, "Hunter2"},
		{`"password": Hunter2`, "Hunter2"},
		{`"X509_check_private_key": "Hunter2"`, "Hunter2"},
		{"    DB_PASSWORD:  Hunter2", "Hunter2"},
		{"      JWT_SECRET:                  Hunter2", "Hunter2"},
	})
}

// F2: prose containing "authorization:" stays readable. A header at a place
// where a header can start, or any value that begins with an authentication
// scheme, is redacted.
func TestAuthorizationProseStaysReadable(t *testing.T) {
	r := builtinOnly(t)
	for _, line := range []string{
		`Warning  Failed  1m  kubelet  Failed to pull image "r/x:1": Error response from daemon: pull access denied for r/x, repository does not exist or may require authorization: server message: insufficient_scope: authorization failed`,
		`time="x" level=warning msg="svc: authorization: disabled for health"`,
		`app: authorization: disabled for health endpoint`,
		`registry returned: authorization: required`,
	} {
		if got := r.Line(line); got != line {
			t.Errorf("changed %q => %q", line, got)
		}
	}
	checkSecretCases(t, r, []secretCase{
		{"Authorization: Hunter2opaque", "Hunter2"},
		{"    Authorization: Hunter2opaque", "Hunter2"},
		{"> Authorization: Basic Hunter2", "Hunter2"},
		{"> Authorization: Hunter2opaque", "Hunter2"},
		{"Proxy-Authorization: Hunter2opaque", "Hunter2"},
		{`curl -H "Authorization: Hunter2opaque" http://h`, "Hunter2"},
		{`curl -H 'Authorization: Hunter2opaque' http://h`, "Hunter2"},
		{`{"Authorization": "Hunter2opaque", "x": 1}`, "Hunter2"},
		{`{"x":1,"authorization":"Hunter2opaque"}`, "Hunter2"},
		{`headers: map[Authorization:[Hunter2opaque]]`, "Hunter2"},
		{`request headers: Authorization: Basic Hunter2`, "Hunter2"},
		{`request headers: authorization: Digest username="u", response="Hunter2"`, "Hunter2"},
		{`msg="req" header="Authorization: Hunter2opaque"`, "Hunter2"},
		{`proxy_set_header Authorization $Hunter2;`, "Hunter2"},
	})
}

// F3: every documented credential word and key prefix, in both forms. A
// prefixed key is used so a rule for the bare words password, secret and token
// cannot hide a missing alternative.
func TestEveryCredentialWordInBothForms(t *testing.T) {
	r := builtinOnly(t)
	words := []string{
		"password", "passwd", "passphrase", "secret", "token", "credential", "credentials",
		"apikey", "api_key", "api-key", "api.key",
		"access_key", "access-key", "secret_key", "private_key", "auth_key", "encryption_key", "encrypt_key", "signing_key",
		"master_key", "app_key", "sign_key", "secret_key_base", "pass", "apiKey", "accessToken", "SecretKey",
	}
	var cases []secretCase
	for i, w := range words {
		v := fmt.Sprintf("Val%dX", i)
		for _, key := range []string{"x_" + w, "x." + w, "x-" + w} {
			cases = append(cases, secretCase{key + "=" + v, v}, secretCase{key + ": " + v, v}, secretCase{key + " : " + v, v})
		}
		cases = append(cases, secretCase{w + "=" + v, v}, secretCase{w + ": " + v, v})
	}
	for i, w := range []string{"pwd"} {
		v := fmt.Sprintf("PwdVal%dX", i)
		cases = append(cases,
			secretCase{"db_" + w + "=" + v, v}, secretCase{"db." + w + "=" + v, v}, secretCase{"db-" + w + "=" + v, v},
			secretCase{"db_" + w + ": " + v, v}, secretCase{w + ": " + v, v},
		)
	}
	checkSecretCases(t, r, cases)
	// The key is replaced together with its prefix, whatever characters it holds.
	checkExact(t, r, [][2]string{
		{"db.pass=Hunter2", "[REDACTED:credential]"},
		{"db-pass=Hunter2", "[REDACTED:credential]"},
		{"my-app.secret_key: Hunter2", "[REDACTED:credential]"},
		{"a1.b-2_c.api_key=Hunter2", "[REDACTED:credential]"},
	})
	for _, w := range []string{"bypass", "compass", "passed", "token_count", "keyboard", "primary_key"} {
		for _, form := range []string{"%s=1", "%s: 1"} {
			if line := fmt.Sprintf(form, w); r.Line(line) != line {
				t.Errorf("changed %q => %q", line, r.Line(line))
			}
		}
	}
	for _, line := range []string{"PWD=/opt/app", "OLDPWD=/home/app"} {
		if got := r.Line(line); got != line {
			t.Errorf("changed %q => %q", line, got)
		}
	}
}

// A query parameter ends at whitespace or '&': the rest of an access log line
// stays readable, the value is hidden.
func TestQueryParameterEndsAtAmpersandOrSpace(t *testing.T) {
	r := builtinOnly(t)
	checkExact(t, r, [][2]string{
		{`127.0.0.1 - - [x] "GET /cb?access_token=Hunter2&state=1 HTTP/1.1" 200 12`, `127.0.0.1 - - [x] "GET /cb?[REDACTED:credential]&state=1 HTTP/1.1" 200 12`},
		{`GET /login?user=bob&password=Hunter2 HTTP/1.1`, `GET /login?user=bob&[REDACTED:credential] HTTP/1.1`},
		{`GET /x?pwd=Hunter2&y=2 HTTP/1.1`, `GET /x?[REDACTED:credential]&y=2 HTTP/1.1`},
		{`GET /x?db_pass=Hunter2;more&y=2 HTTP/1.1`, `GET /x?[REDACTED:credential]&y=2 HTTP/1.1`},
		{`GET /x?token_count=5 HTTP/1.1`, `GET /x?token_count=5 HTTP/1.1`},
	})
}

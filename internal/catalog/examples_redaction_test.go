package catalog

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/redact"
)

func loadExamples(t *testing.T) *Catalog {
	t.Helper()
	c, err := Load("../../examples/catalog")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func exampleRedactor(t *testing.T, c *Catalog, name string) *redact.Redactor {
	t.Helper()
	a, ok := c.Actions[name]
	if !ok {
		t.Fatalf("example action %s does not exist", name)
	}
	r, err := redact.New(a.Redact)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}

type redactionCase struct {
	line   string
	secret string // must not survive; empty when the line must stay unchanged
}

// Credential forms that every configuration reader must hide: properties,
// YAML, JSON, XML elements and XML attributes.
var configCredentialCases = []redactionCase{
	{"db.password=hunter2", "hunter2"},
	{`spring.datasource.password = "s3cr3t pw"`, "s3cr3t"},
	{"client_secret: ymlsecret1", "ymlsecret1"},
	{"  api-key: ymlkey2", "ymlkey2"},
	{`"password":"jsonpw3"`, "jsonpw3"},
	{`  "secretKey": "jsonkey4",`, "jsonkey4"},
	{`{"name":"n","accessKey":"jsonak5","port":1}`, "jsonak5"},
	{`{"token": 87654321}`, "87654321"},
	{`{'password': 'singleq6'}`, "singleq6"},
	{"<password>xmlpw7</password>", "xmlpw7"},
	{`<secretKey type="s"><![CDATA[xmlcd8]]></secretKey>`, "xmlcd8"},
	{`<entry name="password" value="xmlattr9"/>`, "xmlattr9"},
	{`<property value="xmlattr10" name="db.secret"/>`, "xmlattr10"},
	{`<add key="accessKey" value="xmlattr11" />`, "xmlattr11"},
	{`<Resource username="u" password="xmlattr12" />`, "xmlattr12"},
	{"app.name=demo", ""},
	{"server.port=8080", ""},
	{`"name": "n"`, ""},
	{"<name>demo</name>", ""},
	{`<entry name="timeout" value="30"/>`, ""},
}

func checkRedactionCases(t *testing.T, name string, r *redact.Redactor, cases []redactionCase) {
	t.Helper()
	for _, tc := range cases {
		got := r.Line(tc.line)
		if tc.secret == "" {
			if got != tc.line {
				t.Errorf("%s: %q changed to %q", name, tc.line, got)
			}
			continue
		}
		if strings.Contains(got, tc.secret) {
			t.Errorf("%s: %q leaks %q: %q", name, tc.line, tc.secret, got)
		}
	}
}

var configReaders = []string{"app_config_view", "docker_app_config_view", "k8s_configmap_view", "docker_jar_read_entry", "k8s_pod_jar_read_entry"}

func TestExampleConfigReadersRedactStructuredCredentials(t *testing.T) {
	c := loadExamples(t)
	for _, name := range configReaders {
		checkRedactionCases(t, name, exampleRedactor(t, c, name), configCredentialCases)
	}
}

func TestExampleConfigReadersShareOneRuleSet(t *testing.T) {
	c := loadExamples(t)
	want := c.Actions[configReaders[0]].Redact
	for _, name := range configReaders[1:] {
		if got := c.Actions[name].Redact; !reflect.DeepEqual(got, want) {
			t.Errorf("%s redact config differs from %s:\n%+v\n%+v", name, configReaders[0], got, want)
		}
	}
}

func TestExampleRemovedConfigGrepActions(t *testing.T) {
	c := loadExamples(t)
	for _, name := range []string{"app_config_grep", "docker_app_config_grep", "k8s_configmap_grep"} {
		if _, ok := c.Actions[name]; ok {
			t.Errorf("%s still exists: its exit code reveals whether a redacted value matches", name)
		}
	}
}

var fileCredentialCases = []redactionCase{
	{"password: filepw1", "filepw1"},
	{"secret: filesec2", "filesec2"},
	{"token: filetok3", "filetok3"},
	{"client_secret: filecs4", "filecs4"},
	{"  db_password: filepw5", "filepw5"},
	{`{"password":"logpw6","user":"u"}`, "logpw6"},
	{"2026-10-22 10:00:00 INFO login token: logtok7 user=bob", "logtok7"},
	{"Authorization: Basic ZmlsZXVzZXI6ZmlsZXB3", "ZmlsZXVzZXI6ZmlsZXB3"},
	{"Proxy-Authorization: Basic cHJveHl1c2VyOnB3", "cHJveHl1c2VyOnB3"},
	{`Authorization: Digest username="u", response="digestresp8"`, "digestresp8"},
	{`{"Authorization":"Basic anNvbnVzZXI6cHc=","next":"keep"}`, "anNvbnVzZXI6cHc="},
	{`proxy_set_header Authorization "Basic bmdpbng6cHc=";`, "bmdpbng6cHc="},
	{"X-Api-Key: filekey9", "filekey9"},
	{"proxy_set_header X-Api-Key nginxkey10;", "nginxkey10"},
	{"admin:$apr1$Zk3dJf2B$Q1w2E3r4T5y6U7i8O9p0a1", "Q1w2E3r4T5y6U7i8O9p0a1"},
	{"user:$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "abcdefghijklmnopqrstuu"},
	{"user:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=", "W6ph5Mm5Pz8GgiULbPgzG37mj9g="},
	{"user:$6$saltsalt$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./abcdefghijklmnopqrstuv", "abcdefghijklmnopqrstuv"},
	{"proxy_pass http://127.0.0.1:8080;", ""},
	{"listen 80;", ""},
	{"server_name example.com;", ""},
	{"rewrite ^/(.*)$ /x/$1$2 last;", ""},
	{"Content-Type: text/html", ""},
}

func TestExampleFileReadersRedactColonCredentialsHeadersAndHashes(t *testing.T) {
	c := loadExamples(t)
	for _, name := range []string{"docker_file_view", "docker_file_grep", "k8s_pod_file_view", "k8s_pod_file_grep"} {
		checkRedactionCases(t, name, exampleRedactor(t, c, name), fileCredentialCases)
	}
}

// app_config_keys prints key names only; a long base64-style token that
// slips through the key pattern is still masked.
func TestExampleAppConfigKeysMasksLongBase64(t *testing.T) {
	r := exampleRedactor(t, loadExamples(t), "app_config_keys")
	for _, line := range []string{
		"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY3ODkw",
		"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY3OA==",
		"abcDEF0123456789abcDEF0123456789_-xyz",
	} {
		if got := r.Line(line); strings.Contains(got, line[:32]) {
			t.Errorf("%q not masked: %q", line, got)
		}
	}
	for _, line := range []string{"db.password", "spring.datasource.url", "server.port"} {
		if got := r.Line(line); got != line {
			t.Errorf("%q changed to %q", line, got)
		}
	}
}

// Hadoop and Hive style configuration keeps the key and the value in two
// elements. Only the same-line form can be recognised.
var hadoopStyleCases = []redactionCase{
	{"<property><name>fs.s3a.secret.key</name><value>hdfskey13</value></property>", "hdfskey13"},
	{"  <name>javax.jdo.option.ConnectionPassword</name> <value>hivepw14</value>", "hivepw14"},
	{"<property><name>hive.server2.token</name><value><![CDATA[hivetok15]]></value></property>", "hivetok15"},
	{"<name>a.password</name><value>hadooppw16</value><name>b.port</name><value>portkeep</value>", "hadooppw16"},
	{"<name>fs.defaultFS</name><value>hdfs://nn:8020</value>", ""},
	{"<name>hive.metastore.uris</name><value>thrift://meta:9083</value>", ""},
}

func TestExampleConfigReadersRedactSameLineNameValueElements(t *testing.T) {
	c := loadExamples(t)
	for _, name := range configReaders {
		checkRedactionCases(t, name, exampleRedactor(t, c, name), hadoopStyleCases)
	}
	// The unrelated property that shares the line must survive.
	got := exampleRedactor(t, c, "app_config_view").Line(hadoopStyleCases[3].line)
	if !strings.Contains(got, "portkeep") {
		t.Errorf("neighbouring property lost: %q", got)
	}
}

// The grep actions match the original text before redaction, so the exit code
// and the output reveal whether a hidden value contains a string. Their roots
// must therefore hold logs only.
func TestExampleContainerFileGrepSearchesLogDirectoriesOnly(t *testing.T) {
	c := loadExamples(t)
	for _, name := range []string{"docker_file_grep", "k8s_pod_file_grep"} {
		a := c.Actions[name]
		re := regexp.MustCompile(a.Params["path"].Regex)
		for _, p := range []string{"/var/log/app/a.log", "/data/logs/app.log"} {
			if !re.MatchString(p) {
				t.Errorf("%s rejects %s", name, p)
			}
		}
		for _, p := range []string{"/etc/nginx/nginx.conf", "/etc/nginx/conf.d/site.conf", "/etc/passwd", "/var/log/../etc/x"} {
			if re.MatchString(p) {
				t.Errorf("%s accepts %s", name, p)
			}
		}
		if strings.Contains(a.Description+a.Params["path"].Description, "nginx") {
			t.Errorf("%s description still mentions nginx", name)
		}
	}
}

// SHOW VARIABLES rows are checked as "name<TAB>value" by the row pass of the
// MySQL builtin; the rule needs the variable name.
func TestExampleMySQLVariablesRedactsSecretVariables(t *testing.T) {
	r := exampleRedactor(t, loadExamples(t), "mysql_variables")
	checkRedactionCases(t, "mysql_variables", r, []redactionCase{
		{"report_password\trp_s3cr3t_value", "rp_s3cr3t_value"},
		{"wsrep_sst_auth\tsstuser:sstpw1", "sstpw1"},
		{"ssl_key\t/etc/mysql/server-key.pem", "server-key.pem"},
		{"some_secret_x\tsecval2", "secval2"},
		{"api_token\ttokval3", "tokval3"},
		{"validate_password.policy\tstrict\nmore", "more"},
		{"max_connections\t151", ""},
		{"version\t8.0.46", ""},
		{"Variable_name\tValue", ""},
	})
	// Over-redaction is accepted: numeric variables whose names contain key.
	if got := r.Line("key_buffer_size\t8388608"); strings.Contains(got, "8388608") {
		t.Errorf("key_buffer_size not redacted: %q", got)
	}
}

// Statement text can hold credentials in literals. Literals are removed,
// including escaped quotes and hexadecimal forms.
var sqlLiteralCases = []redactionCase{
	{"SELECT 1 FROM t WHERE access_token='tokval1' AND id=5", "tokval1"},
	{`UPDATE u SET user_password="pwval2" WHERE id=5`, "pwval2"},
	{`SELECT 'esc\'aped3 tail' FROM t`, "aped3"},
	{`SELECT 'esc\'aped3 tail' FROM t`, "tail"},
	{`SELECT "dq""inner4" FROM t`, "inner4"},
	{`SELECT 'sq''inner5' FROM t`, "inner5"},
	{`SELECT 'back\\' AS a, 'second6' AS b`, "second6"},
	{"SELECT 0xDEADBEEF7 FROM t", "DEADBEEF7"},
	{"SELECT x'41424344' AS h", "41424344"},
	{"SELECT 1 WHERE n='unterminated8", "unterminated8"},
	{"SELECT 'multi\nline secret9' AS m", "secret9"},
	{"SELECT 'a' AS a, 'b' AS b, token_col FROM t", "'b'"},
	{"SELECT id, name FROM t WHERE n > 5 ORDER BY id", ""},
	{"SET timestamp=1700000000;", ""},
}

func TestExampleMySQLStatementLogsRedactSQLLiterals(t *testing.T) {
	c := loadExamples(t)
	for _, name := range []string{"mysql_processlist", "mysql_slow_log"} {
		checkRedactionCases(t, name, exampleRedactor(t, c, name), sqlLiteralCases)
	}
}

func TestExampleMySQLConfigViewRedactsWsrepSstAuth(t *testing.T) {
	r := exampleRedactor(t, loadExamples(t), "mysql_config_view")
	checkRedactionCases(t, "mysql_config_view", r, []redactionCase{
		{"wsrep_sst_auth = sstuser:sstpw1", "sstpw1"},
		{"wsrep-sst-auth=sstuser:sstpw2", "sstpw2"},
		{`wsrep_sst_auth="sstuser:sstpw3"`, "sstpw3"},
		{"# wsrep_sst_auth=sstuser:sstpw4", "sstpw4"},
		{"password=mysqlpw5", "mysqlpw5"},
		{"[mysqld]", ""},
		{"max_connections=100", ""},
		{"wsrep_cluster_name=prod", ""},
	})
}

func TestExampleRedisConfigFileViewRedactsQuotedDirectives(t *testing.T) {
	r := exampleRedactor(t, loadExamples(t), "redis_config_file_view")
	checkRedactionCases(t, "redis_config_file_view", r, []redactionCase{
		{"requirepass redispw1", "redispw1"},
		{`"requirepass" "redispw2"`, "redispw2"},
		{`'requirepass' redispw3`, "redispw3"},
		{`  "masterauth" "redispw4"`, "redispw4"},
		{`'masterauth' redispw5`, "redispw5"},
		{`"masteruser" replica_user6`, "replica_user6"},
		{`"user" default on >redispw7 ~* +@all`, "redispw7"},
		{`sentinel "auth-pass" mymaster redispw8`, "redispw8"},
		{`"sentinel" 'auth-pass' mymaster redispw9`, "redispw9"},
		{`"tls-key-file-pass" "redispw10"`, "redispw10"},
		{`"rename-command" CONFIG hiddencmd11`, "hiddencmd11"},
		{"port 6379", ""},
		{`"maxmemory" "100mb"`, ""},
		{"sentinel monitor mymaster 10.0.0.1 6379 2", ""},
	})
}

// XML written with the key in an attribute and the value in the element text
// (Spring, Hibernate, Log4j2, web.xml) and TOML keys written in quotes.
var textValueCredentialCases = []redactionCase{
	{`<property name="password">SameLineValuePw</property>`, "SameLineValuePw"},
	{`<property name="password"><value>textpw17</value></property>`, "textpw17"},
	{`<property name="db.secret"><value><![CDATA[textpw18]]></value></property>`, "textpw18"},
	{`<Property name="DB_PASSWORD">Log4jPw</Property>`, "Log4jPw"},
	{`<property name="hibernate.connection.password">hunter2</property>`, "hunter2"},
	{`<parameter name='password'>textpw19</parameter>`, "textpw19"},
	{`<entry key="accessKey">textpw20</entry>`, "textpw20"},
	{`<property value-type="s" name="password">textpw21</property>`, "textpw21"},
	{`<context-param><param-name>db.password</param-name><param-value>textpw22</param-value></context-param>`, "textpw22"},
	{`<init-param><param-name>api.token</param-name><param-value><![CDATA[textpw23]]></param-value></init-param>`, "textpw23"},
	{`<env-entry-name>jdbc/secret</env-entry-name><env-entry-value>textpw24</env-entry-value>`, "textpw24"},
	{`<entry><key>password</key><value>textpw25</value></entry>`, "textpw25"},
	{`"secret-key" = "tomlSk"`, "tomlSk"},
	{`'api-token' = 'tomlTok26'`, "tomlTok26"},
	{`cfg = { "access_key" = "tomlAk27", port = 1 }`, "tomlAk27"},
	{`<property name="timeout">30</property>`, ""},
	{`<property name="password"/>`, ""},
	{`<property name="password" ref="encoder"/>`, ""},
	{`<param-name>timeout</param-name><param-value>30</param-value>`, ""},
	{`<property name="port">8080</property>`, ""},
	{`"port" = 8080`, ""},
	{`"name" = "demo"`, ""},
}

func TestExampleConfigReadersRedactElementTextAndQuotedTomlKeys(t *testing.T) {
	c := loadExamples(t)
	for _, name := range configReaders {
		checkRedactionCases(t, name, exampleRedactor(t, c, name), textValueCredentialCases)
	}
}

// A credential element must not hide the neighbouring elements on the line,
// and an element that is not a credential must not hide a later one.
func TestExampleConfigReadersTextValueRulesStayInsideOneElement(t *testing.T) {
	c := loadExamples(t)
	for _, name := range configReaders {
		r := exampleRedactor(t, c, name)
		for _, tc := range []struct{ line, keep string }{
			{`<property name="password">pw28</property><property name="port">8080</property>`, `<property name="port">8080</property>`},
			{`<property name="url">jdbc:h2:mem</property><property name="password">pw29</property>`, `<property name="url">jdbc:h2:mem</property>`},
			{`<param-name>password</param-name><param-value>pw30</param-value><param-name>port</param-name><param-value>8080</param-value>`, `<param-name>port</param-name><param-value>8080</param-value>`},
			{`<bean name="passwordEncoder"><property name="strength">10</property></bean>`, `<property name="strength">10</property></bean>`},
			{`cfg = { "secret-key" = "tomlSk", port = 8080 }`, `port = 8080 }`},
		} {
			if got := r.Line(tc.line); !strings.Contains(got, tc.keep) {
				t.Errorf("%s: %q lost %q: %q", name, tc.line, tc.keep, got)
			}
		}
	}
}

// nginx directives separate the name from the value with whitespace and end
// with a semicolon. Group A adds the Basic header and htpasswd builtins; these
// rules cover the directives and the headers with names that hold a keyword.
var nginxDirectiveCases = []redactionCase{
	{"fastcgi_param DB_PASSWORD hunter2;", "hunter2"},
	{"    uwsgi_param API_TOKEN tok123;", "tok123"},
	{`scgi_param APP_SECRET "scgi sec4";`, "sec4"},
	{`binddn_passwd "LdapBindPw";`, "LdapBindPw"},
	{`  # binddn_passwd 'LdapBindPw2';`, "LdapBindPw2"},
	{"ssl_password_file /etc/nginx/pw.txt;", "pw.txt"},
	{"set $token abcTok5;", "abcTok5"},
	{"grpc_set_header X-Secret grpcSecret6;", "grpcSecret6"},
	{"proxy_set_header X-Api-Key nginxkey7;", "nginxkey7"},
	{`proxy_set_header Authorization "Basic bmdpbng6cHc=";`, "bmdpbng6cHc="},
	{"add_header X-Auth-Token tok8;", "tok8"},
	{"admin:$apr1$Zk3dJf2B$Q1w2E3r4T5y6U7i8O9p0a1", "Q1w2E3r4T5y6U7i8O9p0a1"},
	{"user:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=", "W6ph5Mm5Pz8GgiULbPgzG37mj9g="},
	{"fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;", ""},
	{"fastcgi_param QUERY_STRING $query_string;", ""},
	{"proxy_pass http://127.0.0.1:8080;", ""},
	{"server_tokens off;", ""},
	{"proxy_cache_key $scheme$host$uri;", ""},
	{"set $upstream app;", ""},
	{"listen 80;", ""},
	{"server_name example.com;", ""},
	{"include /etc/nginx/conf.d/token_map.conf;", ""},
	{"rewrite ^/token /x last;", ""},
}

func TestExampleNginxDirectiveCredentialsAreRedacted(t *testing.T) {
	c := loadExamples(t)
	for _, name := range append([]string{"file_view"}, configReaders...) {
		checkRedactionCases(t, name, exampleRedactor(t, c, name), nginxDirectiveCases)
	}
}

// file_view reaches /etc/nginx; it must hide the same file credentials as the
// container file readers.
func TestExampleFileViewRedactsFileCredentials(t *testing.T) {
	r := exampleRedactor(t, loadExamples(t), "file_view")
	checkRedactionCases(t, "file_view", r, fileCredentialCases)
}

// The container and Pod file readers share the file rule set with file_view,
// including the whitespace-separated nginx directives.
func TestExampleContainerFileActionsRedactNginxDirectives(t *testing.T) {
	c := loadExamples(t)
	for _, name := range []string{"docker_file_view", "docker_file_grep", "k8s_pod_file_view", "k8s_pod_file_grep"} {
		checkRedactionCases(t, name, exampleRedactor(t, c, name), nginxDirectiveCases)
	}
}

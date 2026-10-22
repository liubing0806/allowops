package catalog

import (
	"reflect"
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

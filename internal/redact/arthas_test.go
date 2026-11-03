package redact

import (
	"bytes"
	"strings"
	"testing"
)

// The output of the Arthas L2 commands of the jvm_arthas builtin: watch values as Arthas prints
// objects (indented by the renderer), the trace tree and monitor tables, and jad source.
func TestArthasOutputIsRedacted(t *testing.T) {
	r, err := New(&Config{Builtin: []string{"secrets", "pii"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ input, want string }{
		// Map and Properties entries: @Type[key]:value.
		{"              @String[password]:@String[hunter2],", "              [REDACTED:credential]"},
		{"              @String[db.password]:@String[hunter2],", "              [REDACTED:credential]"},
		{"              @String[spring.datasource.password]:@String[hunter2],", "              [REDACTED:credential]"},
		{"              @String[apiKey]:@String[k-123456],", "              [REDACTED:credential]"},
		{"              @String[ACCESS_TOKEN]:@String[t0k3n],", "              [REDACTED:credential]"},
		{"              @String[secret]:@ArrayList[", "              [REDACTED:credential]"},
		{"              @String[DB_PWD]:@String[hunter2],", "              [REDACTED:credential]"},
		// Fields of an object: name=value.
		{"              password=@String[hunter2],", "              [REDACTED:credential]"},
		{"              secretKey=@String[s3cr3t],", "              [REDACTED:credential]"},
		{"                  token=@String[t0k3n],", "                  [REDACTED:credential]"},
		// Personal data inside values.
		{"              phone=@String[13800138000],", "              phone=@String[[REDACTED:phone]],"},
		{"              idCard=@String[11010519491231002X],", "              idCard=@String[[REDACTED:identity_card]],"},
		{"              card=@String[4111111111111111],", "              card=@String[[REDACTED:bank_card]],"},
		{"          @Long[13800138000],", "          @Long[[REDACTED:phone]],"},
		// Secrets inside string values.
		{"          @String[jdbc:mysql://root:hunter2@db:3306/app],", "          @String[jdbc:[REDACTED:url_credentials]db:3306/app],"},
		{`          @String[{"password":"hunter2"}],`, `          @String[{[REDACTED:credential]}],`},
		{"          @String[password=hunter2&user=alice],", "          @String[[REDACTED:credential]"},
		{"          @String[Authorization: Bearer abc.def],", "          @String[[REDACTED:bearer]"},
		// A trace tree row whose exception message holds a secret.
		{"0\tmethod\tdemo.Login.check\t\t1\t0.068\t0.068\t0.068\tjava.lang.IllegalStateException: bad password=hunter2",
			"0\tmethod\tdemo.Login.check\t\t1\t0.068\t0.068\t0.068\tjava.lang.IllegalStateException: bad [REDACTED:credential]"},
		// jad source.
		{`         private String password = "hunter2";`, `         private String [REDACTED:credential];`},
		{`         private static final String DB_PASSWORD = "hunter2";`, `         private static final String [REDACTED:credential];`},
		{`  /*13*/     this.password = "hunter2";`, `  /*13*/     this.[REDACTED:credential];`},
		{`  /*21*/     props.put("password", "hunter2");`, `  /*21*/     props.put([REDACTED:credential]);`},
		{`             props.setProperty("db.password", "hunter2");`, `             props.setProperty([REDACTED:credential]);`},
		{`             map.put("apiToken", "a\"b");`, `             map.put([REDACTED:credential]);`},
		{`  /*30*/     dataSource.setPassword("hunter2");`, `  /*30*/     dataSource.[REDACTED:credential];`},
		{`             client.setApiKey("k-123456");`, `             client.[REDACTED:credential];`},
		{`             c.setAccessToken( "t0k3n" );`, `             c.[REDACTED:credential];`},
	} {
		if got := r.Line(tc.input); got != tc.want {
			t.Errorf("%q\n got %q\nwant %q", tc.input, got, tc.want)
		}
	}
	// Lines that hold no secret stay as they are.
	for _, line := range []string{
		"              @String[user]:@String[alice],",
		"              @String[tokenCount]:@Integer[5],",
		"              @String[passed]:@Boolean[true],",
		"              @String[keyboard]:@String[us],",
		"              @String[PWD]:@String[/root],",
		"              @String[OLDPWD]:@String[/tmp],",
		"              name=@String[alice],",
		"  @HashMap[isEmpty=false;size=2]",
		"          @String[hunter2],",
		"0\tmethod\tdemo.TokenService.refresh\t\t1\t0.068\t0.068\t0.068\t",
		"1\tcall\tdemo.PasswordEncoder.matches\t39\t1\t0.016\t0.016\t0.016\t",
		"2026-10-26 04:31:01.354863194\tdemo.Login\tcheck\t92\t92\t0\t2.454\t0.027",
		"at demo.Login.checkPassword(Login.java:18)",
		`         String secret;`,
		`             if (password.equals(input)) {`,
		`             user.setPassword(encoder.encode(raw));`,
		`             map.put("password", password);`,
		`             log.info("token refreshed");`,
	} {
		if got := r.Line(line); got != line {
			t.Errorf("%q => %q", line, got)
		}
	}
}

// A watch value of several lines: every line is redacted on its own.
func TestArthasWatchValueIsRedactedLineByLine(t *testing.T) {
	r, err := New(&Config{Builtin: []string{"secrets", "pii"}})
	if err != nil {
		t.Fatal(err)
	}
	input := "# watch\nvalue\n" +
		"  @ArrayList[\n" +
		"      @Object[][\n" +
		"          @HashMap[\n" +
		"              @String[password]:@String[hunter2],\n" +
		"              @String[user]:@String[alice],\n" +
		"          ],\n" +
		"          @User[\n" +
		"              name=@String[alice],\n" +
		"              creds=@Creds[\n" +
		"                  token=@String[t0k3n],\n" +
		"              ],\n" +
		"          ],\n" +
		"      ],\n" +
		"  ]\n"
	var out bytes.Buffer
	if err := r.Stream(strings.NewReader(input), &out, DefaultMaxLine); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.Contains(got, "hunter2") || strings.Contains(got, "t0k3n") || !strings.Contains(got, "@String[alice]") ||
		strings.Count(got, "\n") != strings.Count(input, "\n") {
		t.Fatalf("redacted:\n%s", got)
	}
}

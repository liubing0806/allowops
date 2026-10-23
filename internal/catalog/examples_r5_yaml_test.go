package catalog

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// Statement text is redacted by one pass over the whole text, so the token
// that starts first wins: a literal that contains "-- " or "#" is consumed
// whole, an apostrophe in a comment or in a backtick identifier does not start
// a literal, and a "#" comment is a comment.
var sqlTokenizerCases = []redactionCase{
	// Backtick identifiers with an apostrophe (round 4 injection/I1).
	{"SELECT `it's` FROM t WHERE pw='btsecret1';", "btsecret1"},
	{"SELECT SLEEP(122) AS `it's`, 'btsecret2' FROM (SELECT 1) t", "btsecret2"},
	{"SELECT * FROM `o'brien` WHERE token='btsecret3' AND k='btv3'", "btv3"},
	{"SELECT `a\"b` FROM t WHERE x='btsecret4'", "btsecret4"},
	{"SELECT `a``b'c` FROM t WHERE x='btsecret5'", "btsecret5"},
	{"SELECT `a#b`\n, 'btsecret6'", "btsecret6"},
	{"SELECT `a -- b`\n, 'btsecret7'", "btsecret7"},
	{"SELECT `a/*b`, 'btsecret8', `c*/d`", "btsecret8"},
	// A "-- " inside a literal followed by a later line (round 4 injection/I2).
	{"SELECT 1 FROM t WHERE 'see -- docs'<>'n'\nAND 'dashsecret1'<>'z'", "dashsecret1"},
	{"SELECT 'x -- y' , pw='dashsecret2'", "dashsecret2"},
	{"SELECT \"a -- b\"\n, 'dashsecret3'", "dashsecret3"},
	// An apostrophe in a "#" comment (round 4 injection/I2, docs-tests/F1).
	{"SELECT SLEEP(120) # don't log this\n , pw FROM u WHERE pw = 'LeakPw1ABC';", "LeakPw1ABC"},
	{"SELECT SLEEP(121) # it's a note\nFROM t WHERE 'hashsecret1'<>'z'", "hashsecret1"},
	{"SELECT 1 # it's a note\nFROM t WHERE pw = 'hashsecret2'", "hashsecret2"},
	{"SELECT 'a # b'\n, 'hashsecret3'", "hashsecret3"},
	// Comments, escapes and doubled quotes keep working.
	{"SELECT /* it's */ 1 FROM t WHERE x='cmtsecret1' /* c'd */ AND y='cmtsecret2'", "cmtsecret2"},
	{"SELECT 1 -- it's done\nFROM u WHERE pw='cmtsecret3'", "cmtsecret3"},
	{`SELECT 'esc\'aped1 tail', "dq""inner2", 'sq''inner3', 'back\\', 'second4'`, "second4"},
	{"SELECT 0xDEADBEEF8, x'41424344'", "41424344"},
	// A plain identifier before a literal that holds a backtick: the closing
	// backtick of the identifier must not pair with the backtick in the literal.
	{"SELECT `my-db`.`t` FROM x WHERE a = '*/\n`btsecret9' AND b = 1", "btsecret9"},
	{"SELECT 1 FROM `a/b` '*/\n`btsecret10'", "btsecret10"},
}

// "#" starts a comment in a SHOW PROCESSLIST statement. Slow log headers start
// with "# Time:" and must stay readable, so the log actions do not take it.
func TestExampleMySQLStatementTextRedactsOnLeftmostToken(t *testing.T) {
	c := loadExamples(t)
	checkRedactionCases(t, "mysql_processlist", exampleRedactor(t, c, "mysql_processlist"), sqlTokenizerCases)
	// The log actions redact one line at a time.
	for _, name := range []string{"mysql_slow_log", "mysql_error_log"} {
		r := exampleRedactor(t, c, name)
		for _, tc := range sqlTokenizerCases {
			var out []string
			for _, line := range strings.Split(tc.line, "\n") {
				out = append(out, r.Line(line))
			}
			got := strings.Join(out, "\n")
			switch {
			case tc.secret == "" && got != tc.line:
				t.Errorf("%s: %q changed to %q", name, tc.line, got)
			case tc.secret != "" && strings.Contains(got, tc.secret):
				t.Errorf("%s: %q leaks %q: %q", name, tc.line, tc.secret, got)
			}
		}
	}
}

func TestExampleMySQLLogActionsKeepHashHeaderLines(t *testing.T) {
	c := loadExamples(t)
	for _, name := range []string{"mysql_slow_log", "mysql_error_log"} {
		checkRedactionCases(t, name, exampleRedactor(t, c, name), []redactionCase{
			{"# Time: 2026-10-22T10:00:00.000000Z", ""},
			{"# User@Host: app[app] @ localhost []  Id:    12", ""},
			{"# Query_time: 1.200000  Lock_time: 0.000100 Rows_sent: 1  Rows_examined: 5", ""},
			{"use app;", ""},
		})
	}
}

type sqlGen struct {
	rnd   *rand.Rand
	multi bool // newlines may appear inside tokens, as in one processlist cell
	n     int
}

func (g *sqlGen) pick(list ...string) string { return list[g.rnd.Intn(len(list))] }

func (g *sqlGen) secret() string {
	g.n++
	return fmt.Sprintf("LEAK%d", g.n)
}

func (g *sqlGen) newline() string {
	if g.multi && g.rnd.Intn(3) == 0 {
		return "\n"
	}
	return ""
}

// body returns text that is valid inside a quoted token and holds one secret.
func (g *sqlGen) body(pieces []string) string {
	count := 1 + g.rnd.Intn(4)
	parts := make([]string, 0, count+1)
	for i := 0; i < count; i++ {
		parts = append(parts, g.pick(pieces...), g.newline())
	}
	at := g.rnd.Intn(len(parts) + 1)
	parts = append(parts[:at], append([]string{g.secret()}, parts[at:]...)...)
	return strings.Join(parts, "")
}

func (g *sqlGen) literal() string {
	if g.rnd.Intn(2) == 0 {
		return "'" + g.body([]string{"a", " ", "-- ", "#", "/*", "*/", "`", `"`, `\'`, `\\`, "''", "x", "--"}) + "'"
	}
	return `"` + g.body([]string{"a", " ", "-- ", "#", "/*", "*/", "`", "'", `\"`, `\\`, `""`, "x", "--"}) + `"`
}

func (g *sqlGen) backtick() string {
	if g.rnd.Intn(3) == 0 {
		return "`" + g.pick("id", "name", "my-db", "a/b", "t1") + "`"
	}
	body := g.pick("it's", `say "hi"`, "x#y", "a -- b", "/*c", "d*/", "a b", "``", "o'brien", "q'", "'q", "t ", "x,", "(y)", ".z") + g.newline()
	return "`" + body + "`"
}

func (g *sqlGen) comment() (text string, endsLine bool) {
	switch g.rnd.Intn(3) {
	case 0:
		return "/*" + g.body([]string{"it's", `"x`, "`", " ", "a", "-- ", "#"}) + "*/", false
	case 1:
		return "-- " + g.noNewline(g.body([]string{"it's", `"x`, "`", " ", "a", "#", "/*"})), true
	}
	text = g.noNewline(g.body([]string{"it's", `"x`, "`", " ", "a", "--", "/*"}))
	if !g.multi {
		// The log actions cannot tell a "#" comment from a "# Time:" header, so
		// comment text there is not replaced; it holds no secret in this model.
		text = strings.ReplaceAll(text, "LEAK", "KEEP")
	}
	return "# " + text, true
}

func (g *sqlGen) noNewline(s string) string { return strings.ReplaceAll(s, "\n", " ") }

func (g *sqlGen) statement() string {
	var b strings.Builder
	for i, n := 0, 3+g.rnd.Intn(10); i < n; i++ {
		endsLine := false
		switch g.rnd.Intn(6) {
		case 0, 1:
			b.WriteString(g.literal())
		case 2:
			b.WriteString(g.backtick())
		case 3:
			var c string
			c, endsLine = g.comment()
			b.WriteString(c)
		default:
			b.WriteString(g.pick("SELECT", "FROM", "t", "=", "<>", ",", "(", ")", "1", "u.id", "WHERE", "AND"))
		}
		if endsLine {
			b.WriteString("\n")
		} else {
			b.WriteString(g.pick(" ", " ", "\n", ", "))
		}
	}
	return b.String()
}

// A statement built from valid tokens holds a secret only inside literals and
// comments. Whatever the mix of quotes, backticks, comments and newlines is,
// no secret may survive.
func TestExampleMySQLStatementTextFuzz(t *testing.T) {
	c := loadExamples(t)
	for _, name := range []string{"mysql_processlist", "mysql_slow_log", "mysql_error_log"} {
		r := exampleRedactor(t, c, name)
		g := &sqlGen{rnd: rand.New(rand.NewSource(20261023)), multi: name == "mysql_processlist"}
		leaks := 0
		for i := 0; i < 20000; i++ {
			stmt := g.statement()
			var got string
			if g.multi {
				got = r.Line(stmt)
			} else {
				var out []string
				for _, line := range strings.Split(stmt, "\n") {
					out = append(out, r.Line(line))
				}
				got = strings.Join(out, "\n")
			}
			if strings.Contains(got, "LEAK") {
				leaks++
				if leaks <= 3 {
					t.Errorf("%s: %q leaves a secret: %q", name, stmt, got)
				}
			}
		}
		if leaks > 0 {
			t.Errorf("%s: %d of 20000 statements leak", name, leaks)
		}
	}
}

// The sudo audit record lists the working directory as PWD=. That is not a
// credential, and the line also carries USER= and COMMAND=, which must stay.
// Keys that only contain pwd, such as db_pwd, remain credentials.
var pwdFileReaders = []string{"file_view", "docker_file_view", "k8s_pod_file_view", "docker_file_grep", "k8s_pod_file_grep"}

func TestExampleFileReadersKeepStandalonePWD(t *testing.T) {
	c := loadExamples(t)
	for _, name := range pwdFileReaders {
		checkRedactionCases(t, name, exampleRedactor(t, c, name), []redactionCase{
			{"Oct 22 10:00:04 host sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart app", ""},
			{"Oct 22 10:00:05 host sudo:   deploy : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/cat /etc/shadow", ""},
			{"kernel: OLDPWD=/x ok", ""},
			{"env: pwd=/srv/app", ""},
			{"env: OldPwd=/srv/app", ""},
			{"db_pwd=pwdsecret1", "pwdsecret1"},
			{"DB_PWD=pwdsecret2", "pwdsecret2"},
			{"app.pwd=pwdsecret3", "pwdsecret3"},
			{"dbPwd=pwdsecret4", "pwdsecret4"},
			{"pwd_file=pwdsecret5", "pwdsecret5"},
			{"PWD_DB=pwdsecret6", "pwdsecret6"},
			{"MYSQL_PWD=pwdsecret7", "pwdsecret7"},
			{"x-oldpwd=pwdsecret8", "pwdsecret8"},
			{"password=pwdsecret9", "pwdsecret9"},
		})
		r := exampleRedactor(t, c, name)
		sudo := "sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/id"
		if got := r.Line(sudo); !strings.Contains(got, "USER=root") || !strings.Contains(got, "COMMAND=/usr/bin/id") {
			t.Errorf("%s: sudo record lost fields: %q", name, got)
		}
	}
}

// A configuration file has no working directory entry, and a bare pwd key is a
// connection string password, so the configuration readers keep treating it as
// a credential.
func TestExampleConfigReadersStillRedactStandalonePwdKey(t *testing.T) {
	c := loadExamples(t)
	for _, name := range configReaders {
		checkRedactionCases(t, name, exampleRedactor(t, c, name), []redactionCase{
			{"pwd=cfgpw1", "cfgpw1"},
			{"odbc.connection=Driver=x;uid=app;pwd=cfgpw2", "cfgpw2"},
		})
	}
}

// SHOW STATUS returns about 500 rows. The row limit is the builtin maximum, and
// a LIKE pattern selects the few variables that are wanted.
func TestExampleMySQLShowStatusAcceptsLikePatternAndAllowsFullRowLimit(t *testing.T) {
	a := loadExamples(t).Actions["mysql_show"]
	def := a.Params["sql"]
	re := regexp.MustCompile(def.Regex)
	for _, sql := range []string{
		"SHOW TABLES", "SHOW STATUS", "SHOW GLOBAL STATUS",
		"SHOW STATUS LIKE 'Threads_connected'", "SHOW GLOBAL STATUS LIKE 'Slow_queries'",
		"SHOW STATUS LIKE 'Com_%'", "SHOW GLOBAL STATUS LIKE 'Uptime'",
		"SHOW GLOBAL STATUS LIKE '" + strings.Repeat("a", 64) + "'",
	} {
		if !re.MatchString(sql) {
			t.Errorf("sql regex rejects %q", sql)
		}
		if def.MaxLen < len(sql) {
			t.Errorf("max_len %d is shorter than %q", def.MaxLen, sql)
		}
	}
	for _, sql := range []string{
		"SHOW STATUS WHERE Variable_name='Uptime'", "SHOW SESSION STATUS", "SHOW STATUS LIKE ''",
		"SHOW STATUS LIKE 'a'; DROP TABLE t", "SHOW STATUS LIKE \"Uptime\"", "SHOW TABLES LIKE 'x'",
		"SHOW STATUS LIKE 'a b'", "SHOW STATUS LIKE '" + strings.Repeat("a", 65) + "'", "SHOW STATUS\n", "show status",
	} {
		if re.MatchString(sql) {
			t.Errorf("sql regex accepts %q", sql)
		}
	}
	if got := a.BuiltinConfig["max_rows"]; got != 500 {
		t.Errorf("max_rows = %v, want 500 (the builtin maximum; SHOW STATUS returns about 500 rows)", got)
	}
	if !strings.Contains(a.Description+def.Description, "500") {
		t.Errorf("description does not state the row limit: %q / %q", a.Description, def.Description)
	}
}

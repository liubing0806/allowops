package catalog

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

var mysqlStatementActions = []string{"mysql_processlist", "mysql_slow_log", "mysql_error_log"}

// Literals that hold text a built-in rule redacts (a Bearer header, a -p
// option, password=...) must not change how the quotes of the statement pair.
// The built-in rules consume a closing quote in some forms, so a later literal
// would be read as code and stay readable.
func TestExampleMySQLStatementTextIsRedactedBeforeBuiltinRules(t *testing.T) {
	c := loadExamples(t)
	cases := []redactionCase{
		{`SELECT 1 WHERE h = 'Authorization: Bearer abcd' AND x = 'LEAKSEP1'`, "LEAKSEP1"},
		{`SELECT 1 WHERE h = "Authorization: Bearer abcd" AND x = "LEAKSEP2"`, "LEAKSEP2"},
		{`INSERT INTO t VALUES ('mysql -pabcd'), ('LEAKSEP3')`, "LEAKSEP3"},
		{`INSERT INTO t VALUES ('curl -u a:b'), ('LEAKSEP4')`, "LEAKSEP4"},
		{`INSERT INTO t VALUES ('redis-cli -a abcd'), ('LEAKSEP5')`, "LEAKSEP5"},
		{`INSERT INTO t VALUES ('sshpass -p abcd'), ('LEAKSEP6')`, "LEAKSEP6"},
		{`INSERT INTO t VALUES ('password=hunter2'), ('LEAKSEP7')`, "LEAKSEP7"},
		{`INSERT INTO t VALUES ('token: hunter2'), ('LEAKSEP8')`, "LEAKSEP8"},
		{`SET PASSWORD='LEAKSEP9'`, "LEAKSEP9"},
	}
	for _, name := range mysqlStatementActions {
		checkRedactionCases(t, name, exampleRedactor(t, c, name), cases)
	}
}

type credentialLiteralGen struct {
	rnd    *rand.Rand
	n      int
	embed  []string // secrets inside literals
	secret string   // the separate secret literal of the statement
}

func (g *credentialLiteralGen) pick(list ...string) string { return list[g.rnd.Intn(len(list))] }

func (g *credentialLiteralGen) embedded() string {
	g.n++
	s := fmt.Sprintf("EMBED%d", g.n)
	g.embed = append(g.embed, s)
	return s
}

// piece is text inside a literal. The quote q is doubled by the caller.
func (g *credentialLiteralGen) piece() string {
	switch g.rnd.Intn(15) {
	case 0:
		return "password=" + g.embedded()
	case 1:
		return "token: " + g.embedded()
	case 2:
		return "pwd=" + g.embedded()
	case 3:
		return "secret=" + g.embedded() + " "
	case 4:
		return "password='" + g.embedded() + "'"
	case 5:
		return `password="` + g.embedded() + `"`
	case 6:
		return "api_key: " + g.embedded()
	case 7:
		return "--password " + g.embedded()
	case 8:
		return "Authorization: Bearer " + g.embedded()
	case 9:
		return "mysql://u:" + g.embedded() + "@h/"
	case 10:
		return "mysql -p" + g.embedded() + " "
	case 11:
		return g.pick("curl -u a:"+g.embedded()+" ", "redis-cli -a "+g.embedded()+" ")
	case 12:
		return g.pick(`\\`, "ESC", "''", `""`, "'", `"`, "`", "-- ", "#", "/*", "*/", "(", ")", ",")
	case 13:
		return g.pick("a", " ", "x ", "VALUES ", "= ")
	}
	return g.pick("password=", "token:", "pwd=", "secret=") // key without a value
}

// literal returns a valid MySQL string literal: a quote of its own kind is
// doubled or escaped.
func (g *credentialLiteralGen) literal(q byte) string {
	var b strings.Builder
	b.WriteByte(q)
	for i, n := 0, g.rnd.Intn(5); i < n; i++ {
		p := g.piece()
		if p == "ESC" {
			p = `\` + string(q)
		} else {
			p = strings.ReplaceAll(p, string(q), string(q)+string(q))
		}
		b.WriteString(p)
	}
	b.WriteByte(q)
	return b.String()
}

func (g *credentialLiteralGen) statement() string {
	g.embed = nil
	g.n++
	g.secret = fmt.Sprintf("SECRET%d", g.n)
	at := g.rnd.Intn(6)
	var b strings.Builder
	b.WriteString(g.pick("INSERT INTO t VALUES (", "UPDATE t SET a=(", "SELECT (", "SELECT 1 FROM t WHERE a=("))
	for i := 0; i < 6; i++ {
		q := byte('\'')
		if g.rnd.Intn(4) == 0 {
			q = '"'
		}
		if i > 0 {
			b.WriteString(g.pick(", ", "), (", " AND b=", ") , (", " OR x = ", " "))
		}
		if i == at {
			b.WriteString(string(q) + g.secret + string(q))
		} else {
			b.WriteString(g.literal(q))
		}
	}
	b.WriteString(")")
	return b.String()
}

// Every literal of a valid statement is redacted, whatever credential forms
// the other literals contain, so neither the separate secret literal nor a
// secret inside a literal may survive.
func TestExampleMySQLStatementTextFuzzWithCredentialLiterals(t *testing.T) {
	c := loadExamples(t)
	for _, name := range mysqlStatementActions {
		r := exampleRedactor(t, c, name)
		g := &credentialLiteralGen{rnd: rand.New(rand.NewSource(20261023))}
		const total = 30000
		leaks := 0
		for i := 0; i < total; i++ {
			stmt := g.statement()
			got := r.Line(stmt)
			leaked := strings.Contains(got, g.secret)
			for _, e := range g.embed {
				leaked = leaked || strings.Contains(got, e)
			}
			if leaked {
				leaks++
				if leaks <= 3 {
					t.Errorf("%s: %q => %q", name, stmt, got)
				}
			}
		}
		if leaks > 0 {
			t.Errorf("%s: %d of %d statements leak", name, leaks, total)
		}
	}
}

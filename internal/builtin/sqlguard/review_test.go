package sqlguard

import "testing"

// The local Dremio 24.1 image extracts /* ... */ comments from the raw SQL text
// with a regular expression that ignores string literals and quoted
// identifiers, and turns set_var.x=v entries into a SET_VAR hint on the
// statement it pushes down to the data source. The statements below produced
// SELECT /*+ SET_VAR("pipeline_dop"= '2') */ and '3' in the pushed-down SQL.
func TestReviewSetVarOutsideCommentIsRejected(t *testing.T) {
	for _, sql := range []string{
		`SELECT count(*) AS c FROM src.db.t WHERE 'x' <> '/* set_var.pipeline_dop=2 */'`,
		`SELECT count(*) AS "/* set_var.pipeline_dop=3 */" FROM src.db.t`,
	} {
		if st, err := Validate(Dremio, sql, Options{}); err == nil {
			t.Errorf("Dremio accepted %q: %+v", sql, st)
		}
	}
}

// The rule is limited to Dremio: only Dremio was measured to read a comment out
// of quoted text, and StarRocks keeps its lexical rules.
func TestSetVarInQuotesRuleIsDremioOnly(t *testing.T) {
	for _, sql := range []string{
		`SELECT 1 FROM t WHERE 'x' <> '/* set_var.pipeline_dop=2 */'`,
		"SELECT 1 FROM t WHERE `x` <> '/* set_var.pipeline_dop=2 */'",
	} {
		if _, err := Validate(StarRocks, sql, Options{}); err != nil {
			t.Errorf("StarRocks rejected %q: %v", sql, err)
		}
	}
}

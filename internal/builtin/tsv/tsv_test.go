package tsv

import (
	"database/sql"
	"reflect"
	"strings"
	"testing"
)

func cells(values ...any) []sql.NullString {
	out := make([]sql.NullString, len(values))
	for i, v := range values {
		if s, ok := v.(string); ok {
			out[i] = sql.NullString{String: s, Valid: true}
		}
	}
	return out
}

func TestMaskRowKeepsCellsWhenNoRuleMatches(t *testing.T) {
	got := MaskRow(cells("max_connections", "151", nil, "a\tb"), func(s string) string { return s })
	want := []string{"max_connections", "151", `\N`, `a\tb`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMaskRowAppliesRulesToEachCell(t *testing.T) {
	mask := func(s string) string { return strings.ReplaceAll(s, "secret", "[R]") }
	got := MaskRow(cells("a", "my secret"), mask)
	if want := []string{"a", "my [R]"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// A rule that needs the name cell to decide about the value cell sees the
// tab-joined row. The whole row is replaced, so neither the name nor the
// value remains and the field count is not trusted.
func TestMaskRowLetsRulesRelateNameToValue(t *testing.T) {
	mask := func(s string) string {
		if strings.HasPrefix(s, "report_password\t") {
			return "[REDACTED:row]"
		}
		return s
	}
	got := MaskRow(cells("report_password", "rp_s3cr3t"), mask)
	if want := []string{"[REDACTED:row]"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	got = MaskRow(cells("max_connections", "151"), mask)
	if want := []string{"max_connections", "151"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// A rule that keeps the tab structure replaces only the value cell.
func TestMaskRowKeepsFieldsWhenRowRuleKeepsTabs(t *testing.T) {
	mask := func(s string) string { return strings.Replace(s, "\tvalue", "\t[R]", 1) }
	got := MaskRow(cells("name", "value", nil), mask)
	if want := []string{"name", "[R]", `\N`}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// A cell that contains a tab makes the field boundaries ambiguous. When a
// row rule changes such a row, the row collapses instead of splitting wrongly.
func TestMaskRowFailsClosedWhenFieldBoundariesAreAmbiguous(t *testing.T) {
	mask := func(s string) string { return strings.ReplaceAll(s, "secret", "[R]") }
	got := MaskRow(cells("a\tb", "c"), func(s string) string {
		if strings.Contains(s, "\t") {
			return mask(s + "secret")
		}
		return s
	})
	if len(got) != 1 || strings.Contains(got[0], "\t") {
		t.Fatalf("got %q", got)
	}
}

// A row rule can remove exactly as many tabs as a cell contains, so the tab
// count matches the cell count while the boundaries are shifted. A row with an
// embedded tab that a row rule changed must collapse into one field.
func TestMaskRowCollapsesWhenRowRuleChangesRowWithEmbeddedTab(t *testing.T) {
	mask := func(s string) string { return strings.ReplaceAll(s, "password=\tv", "[R]") }
	got := MaskRow(cells("a\tb", "password=", "v"), mask)
	if len(got) != 1 || strings.Contains(got[0], "\t") || strings.Contains(got[0], "\tv") {
		t.Fatalf("got %q, want one field without a raw tab", got)
	}
}

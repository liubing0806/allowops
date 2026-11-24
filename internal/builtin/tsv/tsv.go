// Package tsv encodes database result rows as the tab-separated text that the
// database builtins return: escaped fields, \N for NULL, and per-cell masking.
package tsv

import (
	"database/sql"
	"slices"
	"strings"
)

// MaskRow returns the TSV fields of one row. Every cell is masked on its own
// first. The tab-joined row is then masked again so that a rule can relate a
// name cell to its value cell, as SHOW VARIABLES needs. When that pass changes
// the row, the fields are taken from the result only when no cell contains a
// tab and the tab count still matches; otherwise the row collapses into one
// field. An embedded tab makes the boundaries ambiguous, because a rule that
// removes as many tabs as a cell holds leaves the count unchanged but shifts
// every field.
func MaskRow(values []sql.NullString, mask func(string) string) []string {
	return MaskRowWith(values, mask, mask)
}

// MaskRowWith returns the TSV fields of one row, masking each cell with
// maskValue and then the tab-joined row with maskJoined. Passing a stateful
// maskValue and a stateless maskJoined ensures only original cell values
// advance cross-value redaction state such as PEM blocks.
func MaskRowWith(values []sql.NullString, maskValue, maskJoined func(string) string) []string {
	cells := make([]string, len(values))
	for i, v := range values {
		if v.Valid {
			cells[i] = maskValue(v.String)
		}
	}
	if len(cells) > 1 {
		joined := strings.Join(cells, "\t")
		if masked := maskJoined(joined); masked != joined {
			parts := strings.Split(masked, "\t")
			if len(parts) != len(cells) || slices.ContainsFunc(cells, func(c string) bool { return strings.Contains(c, "\t") }) {
				return []string{Escape(masked)}
			}
			for i, v := range values {
				if v.Valid {
					cells[i] = parts[i]
				}
			}
		}
	}
	fields := make([]string, len(cells))
	for i, v := range values {
		if v.Valid {
			fields[i] = Escape(cells[i])
		} else {
			fields[i] = `\N`
		}
	}
	return fields
}

var escaper = strings.NewReplacer("\\", "\\\\", "\t", `\t`, "\n", `\n`, "\r", `\r`, "\x00", `\0`)

// Escape escapes backslash, tab, newline, carriage return and NUL.
func Escape(s string) string { return escaper.Replace(s) }

// WriteRow writes one escaped, tab-separated line, such as the header.
func WriteRow(out *strings.Builder, fields []string) {
	for i, field := range fields {
		if i > 0 {
			out.WriteByte('\t')
		}
		out.WriteString(Escape(field))
	}
	out.WriteByte('\n')
}

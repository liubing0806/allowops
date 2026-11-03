package redact

import "testing"

func piiRedactor(t *testing.T) *Redactor {
	t.Helper()
	r, err := New(&Config{Builtin: []string{"pii"}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Digits that belong to a longer token or a decimal number are not card
// numbers, even when the digits pass the Luhn check.
func TestBankCardIgnoresDigitsInsideOtherTokens(t *testing.T) {
	r := piiRedactor(t)
	for _, input := range []string{
		"sr-fe_9010_1729837261232",
		"sr-fe_9010_1729837261232 ALIVE true",
		"id=abc1729837261232",
		"1729837261232ms",
		"sr_1729837261232_fe",
		"0.1234567890123452",
		"load\t0.1234567890123452\t0.5",
		"4532015112830366.25",
		"cpu=-0.1234567890123452",
	} {
		if got := r.Line(input); got != input {
			t.Errorf("false positive %q => %q", input, got)
		}
	}
}

// A card number written as a standalone value stays redacted. A bare integer
// column such as a byte count has the same text and is redacted too.
func TestBankCardRedactsStandaloneNumbers(t *testing.T) {
	r := piiRedactor(t)
	for _, tc := range []struct{ input, want string }{
		{"4532015112830366", "[REDACTED:bank_card]"},
		{"card=4532015112830366", "card=[REDACTED:bank_card]"},
		{"card: 4532015112830366", "card: [REDACTED:bank_card]"},
		{`{"card":"4532015112830366"}`, `{"card":"[REDACTED:bank_card]"}`},
		{"card 4532015112830366.", "card [REDACTED:bank_card]."},
		{"(4532015112830366)", "([REDACTED:bank_card])"},
		{"a,4532015112830366,b", "a,[REDACTED:bank_card],b"},
		{"1729837261232\t12", "[REDACTED:bank_card]\t12"},
		{"scanBytes\t4532015112830366", "scanBytes\t[REDACTED:bank_card]"},
	} {
		if got := r.Line(tc.input); got != tc.want {
			t.Errorf("%q => %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestIdentityCardIgnoresDigitsInsideOtherTokens(t *testing.T) {
	r := piiRedactor(t)
	for _, input := range []string{"0.123456789012345677", "id_123456789012345677", "123456789012345677.5"} {
		if got := r.Line(input); got != input {
			t.Errorf("false positive %q => %q", input, got)
		}
	}
	for _, tc := range []struct{ input, want string }{
		{"123456789012345677", "[REDACTED:identity_card]"},
		{"id=11010519491231002X", "id=[REDACTED:identity_card]"},
	} {
		if got := r.Line(tc.input); got != tc.want {
			t.Errorf("%q => %q, want %q", tc.input, got, tc.want)
		}
	}
}

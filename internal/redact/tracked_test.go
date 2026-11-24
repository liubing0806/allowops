package redact

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestLineTracked(t *testing.T) {
	r, err := New(&Config{Custom: []Rule{{Name: "fixture", Regex: "fixture-value"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		raw, want string
		modified  bool
	}{
		{"plain", "plain", false},
		{"password=fixture", "[REDACTED:credential]", true},
		{"fixture-value", "[REDACTED:fixture]", true},
		{"start -----BEGIN PRIVATE KEY----- body", "start [REDACTED:pem_private_key]", true},
		{"plain again", "plain again", false},
	} {
		got, modified := r.LineTracked(tc.raw)
		if got != tc.want || modified != tc.modified || got != r.Line(tc.raw) {
			t.Errorf("LineTracked(%q) = (%q, %t), want (%q, %t)", tc.raw, got, modified, tc.want, tc.modified)
		}
	}
}

func TestStreamTrackedTracksPEMLines(t *testing.T) {
	r, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := "plain\nstart -----BEGIN PRIVATE KEY-----\n\nbody\n-----END PRIVATE KEY-----rest\npassword=fixture\nlast"
	type entry struct {
		text     string
		modified bool
	}
	var lines []entry
	err = r.StreamTracked(strings.NewReader(raw), DefaultMaxLine, func(line string, modified bool) error {
		lines = append(lines, entry{line, modified})
		return nil
	})
	want := []entry{{"plain\n", false}, {"start [REDACTED:pem_private_key]\n", true}, {"\n", true}, {"\n", true}, {"rest\n", true}, {"[REDACTED:credential]\n", true}, {"last", false}}
	if err != nil || !slices.Equal(lines, want) {
		t.Fatalf("lines=%+v, err=%v, want %+v", lines, err, want)
	}

	var streamed strings.Builder
	if err := r.Stream(strings.NewReader(raw), &streamed, DefaultMaxLine); err != nil {
		t.Fatal(err)
	}
	var tracked strings.Builder
	for _, line := range lines {
		tracked.WriteString(line.text)
	}
	if tracked.String() != streamed.String() {
		t.Fatalf("stream=%q, tracked=%q", streamed.String(), tracked.String())
	}
}

func TestStreamTrackedLimitsAndCallbackError(t *testing.T) {
	r := &Redactor{}
	const maxLine = 70 * 1024
	full := strings.Repeat("a", maxLine)
	for _, suffix := range []string{"", "\n"} {
		input := full + suffix
		var lines []string
		if err := r.StreamTracked(strings.NewReader(input), maxLine, func(line string, modified bool) error {
			if modified {
				t.Error("unmodified line marked as modified")
			}
			lines = append(lines, line)
			return nil
		}); err != nil || !slices.Equal(lines, []string{input}) {
			t.Fatalf("length=%d, emitted lines=%d, err=%v", len(input), len(lines), err)
		}
	}
	for _, input := range []string{full + "x", full + "x\n"} {
		if err := r.StreamTracked(strings.NewReader(input), maxLine, func(string, bool) error {
			t.Fatal("overlong line was emitted")
			return nil
		}); err == nil {
			t.Fatal("overlong line was accepted")
		}
	}
	want := errors.New("callback stopped")
	if err := r.StreamTracked(strings.NewReader("ok\nnext\n"), 4, func(line string, _ bool) error {
		if line != "ok\n" {
			t.Fatalf("callback ran after failure: %q", line)
		}
		return want
	}); !errors.Is(err, want) {
		t.Fatalf("err=%v, want %v", err, want)
	}
}

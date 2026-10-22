package catalog

import (
	"encoding/json"
	"math"
	"testing"
)

func TestParseSizeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input any
		want  int64
		fail  bool
	}{
		{"zero_integer", 0, 0, false}, {"zero_string", "0", 0, false}, {"zero_unit", "0KB", 0, false},
		{"integer_bytes", 42, 42, false}, {"without_unit", "42", 42, false}, {"int64_max", int64(math.MaxInt64), math.MaxInt64, false},
		{"KB", "64KB", 65536, false}, {"MB", "2MB", 2097152, false}, {"GB", "1GB", 1073741824, false},
		{"lowercase", "64kb", 65536, false}, {"mixed_case", "2mB", 2097152, false}, {"bytes_unit", "3B", 3, false},
		{"largest_KB", "9007199254740991KB", 9223372036854774784, false},
		{"unit_overflow", "9007199254740992KB", 0, true}, {"integer_overflow", "9223372036854775808", 0, true},
		{"uint_overflow", uint64(math.MaxUint64), 0, true}, {"negative_integer", -1, 0, true}, {"negative_string", "-1KB", 0, true},
		{"bad_suffix", "1TB", 0, true}, {"fraction", "1.5MB", 0, true}, {"fraction_number", 1.5, 0, true}, {"empty", "", 0, true},
		{"whitespace", "1 KB", 0, true}, {"boolean", true, 0, true}, {"null", nil, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSize(tc.input)
			if (err != nil) != tc.fail || (!tc.fail && got != tc.want) {
				t.Fatalf("ParseSize(%#v)=%d,%v; want %d failure=%v", tc.input, got, err, tc.want, tc.fail)
			}
		})
	}
}

func TestSizeNormalizedAtDecode(t *testing.T) {
	for _, raw := range []string{"max_output: 2kb", "max_output: 2048"} {
		a, err := ParseAction([]byte("name: echo\ndescription: echo\nrisk: read\nexec: [/bin/echo]\ntimeout: 1s\n" + raw + "\n"))
		if err != nil || a.MaxOutput != 2048 {
			t.Fatalf("%s => %d, %v", raw, a.MaxOutput, err)
		}
		data, err := CanonicalJSON(a)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		if string(fields["max_output"]) != "2048" {
			t.Fatal(string(data))
		}
	}
	a, err := ParseAction([]byte("name: echo\ndescription: echo\nrisk: read\nexec: [/bin/echo]\ntimeout: 1s\nmax_output: 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	a = applyDefaults(a, Config{Defaults: Defaults{MaxOutput: 1024}})
	if _, err := ValidateAction(a); err == nil {
		t.Fatal("accepted zero max_output")
	}
}

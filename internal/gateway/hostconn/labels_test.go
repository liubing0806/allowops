package hostconn

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestReportedLabelLimitsConfiguration(t *testing.T) {
	config := DefaultConfig()
	decoder := yaml.NewDecoder(strings.NewReader("reported_label_count: 1\nreported_label_key_bytes: 3\nreported_label_value_bytes: 4\n"))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		t.Fatalf("Q1 reported label limits not configurable: %v", err)
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	s := &Service{Config: config}
	for _, tc := range []struct {
		name   string
		labels map[string]string
		valid  bool
	}{
		{"empty", nil, true},
		{"byte_boundaries", map[string]string{"abc": "1234"}, true},
		{"utf8_boundaries", map[string]string{"键": "值a"}, true},
		{"count", map[string]string{"a": "1", "b": "2"}, false},
		{"key_bytes", map[string]string{"键键": ""}, false},
		{"value_bytes", map[string]string{"a": "值值"}, false},
		{"empty_key", map[string]string{"": "x"}, false},
		{"invalid_utf8", map[string]string{"a": string([]byte{0xff})}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.validateLabels(tc.labels); (err == nil) != tc.valid {
				t.Fatalf("validateLabels=%v, valid=%v", err, tc.valid)
			}
		})
	}
	for _, key := range []string{"reported_label_count: 129", "reported_label_key_bytes: 129", "reported_label_value_bytes: 1025", "reported_label_count: 0"} {
		config := DefaultConfig()
		if err := yaml.Unmarshal([]byte(key), &config); err != nil {
			t.Fatal(err)
		}
		if err := config.Validate(); err == nil {
			t.Fatalf("accepted invalid limit %s", key)
		}
	}
}

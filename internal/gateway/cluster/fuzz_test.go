package cluster

import (
	"math"
	"reflect"
	"testing"
	"unicode/utf8"
)

func FuzzNormalize(f *testing.F) {
	seeds := [][]byte{
		[]byte("token=[REDACTED:secrets] host=web-01 ip=10.0.0.1:8080 pid=42 cpu=96.5% mem=512MiB dur=2h 30min"),
		[]byte(`{"heap_used":1024,"full_gc":0,"exit_code":1,"records":[{"msg":"timeout 120ms"}]}`),
		[]byte("{\"ID\":\"a1b2c3d4e5f6\",\"Status\":\"Exited (137) 5 minutes ago\"}\n{\"ID\":\"11223344aabb\",\"Status\":\"Up 3 hours\"}\n"),
		[]byte("HTTP/1.1 500 Internal Server Error nginx/1.25.3 v1.27.3-rc.1"),
		[]byte("2026-11-24T12:34:56.789+08:00 24/Nov/2026:12:34:56 +0800 Nov 24 12:34:56 [12345]: 550e8400-e29b-41d4-a716-446655440000"),
		[]byte("\x00\xff\xfe\x1b[31m1e999 -1e999 NaN [REDACTED:a]"),
		[]byte(`{{{{{{{{{{{{{{{{{{{{`),
	}
	for _, s := range seeds {
		f.Add(s, "web-01.prod.local", true, false)
	}

	f.Fuzz(func(t *testing.T, data []byte, hostname string, maskIPs bool, truncated bool) {
		opts := NormalizeOptions{
			Hostname:  hostname,
			MaskIPs:   maskIPs,
			Truncated: truncated,
		}
		r1 := NormalizePreview(data, opts)
		r2 := NormalizePreview(data, opts)

		if !reflect.DeepEqual(r1, r2) {
			t.Fatalf("non-deterministic NormalizePreview output")
		}
		if !utf8.ValidString(r1.Template) {
			t.Fatalf("invalid UTF-8 template: %q", r1.Template)
		}
		if len(r1.Slots) > MaxSlotsPerTask {
			t.Fatalf("slots exceeded MaxSlotsPerTask: %d", len(r1.Slots))
		}
		for _, sl := range r1.Slots {
			if math.IsNaN(sl.Value) || math.IsInf(sl.Value, 0) {
				t.Fatalf("non-finite slot value: %+v", sl)
			}
			if !utf8.ValidString(sl.Label) || len(sl.Label) > MaxLabelBytes {
				t.Fatalf("invalid slot label: %q", sl.Label)
			}
			if !utf8.ValidString(sl.Unit) || len(sl.Unit) > MaxLabelBytes {
				t.Fatalf("invalid slot unit: %q", sl.Unit)
			}
			for i := 0; i < len(sl.Label); i++ {
				if sl.Label[i] < 0x20 || sl.Label[i] == 0x7f {
					t.Fatalf("control byte in label: %q", sl.Label)
				}
			}
			for i := 0; i < len(sl.Unit); i++ {
				if sl.Unit[i] < 0x20 || sl.Unit[i] == 0x7f {
					t.Fatalf("control byte in unit: %q", sl.Unit)
				}
			}
		}
	})
}

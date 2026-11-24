package cluster

import (
	"bytes"
	"math"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNormalizeRedactedProtected(t *testing.T) {
	raw := []byte("token=[REDACTED:secrets] host=web-01 pid=12345 ip=10.0.0.1 [REDACTED:12345-deadbeef]")
	res := NormalizePreview(raw, DefaultNormalizeOptions("web-01.prod.internal"))
	want := "token=[REDACTED:secrets] host=<HOST> pid=<PID> ip=<IP> [REDACTED:12345-deadbeef]"
	if res.Template != want {
		t.Fatalf("got %q, want %q", res.Template, want)
	}
}

func TestNormalizeHostnameAndShortName(t *testing.T) {
	// Eligible short hostname: length >= 3 and has digit or hyphen.
	res := NormalizePreview([]byte("from web-01.prod.local and web-01 but not web-010 or myweb-01"), DefaultNormalizeOptions("web-01.prod.local"))
	want := "from <HOST> and <HOST> but not web-<NUM> or myweb-<NUM>"
	// Note: "web-010" has '-' after 'b', so "010" is protected as hyphenated identifier!
	want = "from <HOST> and <HOST> but not web-010 or myweb-01"
	if res.Template != want {
		t.Fatalf("got %q, want %q", res.Template, want)
	}

	// Short hostname without digit or hyphen ("app") must NOT be masked as short name.
	res2 := NormalizePreview([]byte("app running on app.prod.local"), DefaultNormalizeOptions("app.prod.local"))
	want2 := "app running on <HOST>"
	if res2.Template != want2 {
		t.Fatalf("got %q, want %q", res2.Template, want2)
	}

	// Short hostname shorter than 3 ("a1") must NOT be masked as short name.
	res3 := NormalizePreview([]byte("a1 on a1.prod.local"), DefaultNormalizeOptions("a1.prod.local"))
	want3 := "a1 on <HOST>"
	if res3.Template != want3 {
		t.Fatalf("got %q, want %q", res3.Template, want3)
	}
}

func TestNormalizeTimestampsAndClock(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"2026-11-24T12:34:56Z ok", "<TS> ok"},
		{"2026-11-24T12:34:56.789+08:00 ok", "<TS> ok"},
		{"2026-11-24 12:34:56 +0800 CST ok", "<TS> ok"},
		{"2026/11/24 09:05:01 ok", "<TS> ok"},
		{"24/Nov/2026:12:34:56 +0800 ok", "<TS> ok"},
		{"Nov 24 12:34:56 sshd[42]: accepted", "<TS> sshd[<PID>]: accepted"},
		{"Mon 2026-11-24 10:00:00 UTC; 2h 30min ago", "<TS>; <DUR> ago"},
		{" 12:34:56 up 42 days, 3:15", " <TIME> up <DUR>, <NUM>:<NUM>"},
		{"at 08:01:02.123 done", "at <TIME> done"},
	}
	for _, tc := range cases {
		res := NormalizePreview([]byte(tc.in), DefaultNormalizeOptions(""))
		if res.Template != tc.want {
			t.Errorf("in=%q: got %q, want %q", tc.in, res.Template, tc.want)
		}
	}
}

func TestNormalizeUUIDIPHex(t *testing.T) {
	in := "req=550e8400-e29b-41d4-a716-446655440000 ip=10.20.30.40:8080 cidr=192.168.1.0/24 v6=[2001:db8::1]:443 bare=fe80::1 cid=a1b2c3d4e5f6 ptr=0x7fff12ab word=deadbeef"
	res := NormalizePreview([]byte(in), DefaultNormalizeOptions(""))
	want := "req=<UUID> ip=<IP_PORT> cidr=<IP> v6=<IP_PORT> bare=<IP> cid=<HEX> ptr=<HEX> word=deadbeef"
	if res.Template != want {
		t.Fatalf("MaskIPs=true:\ngot  %q\nwant %q", res.Template, want)
	}

	// MaskIPs = false must preserve IPs verbatim (not convert octets to <NUM>).
	opts := DefaultNormalizeOptions("")
	opts.MaskIPs = false
	resNoMask := NormalizePreview([]byte(in), opts)
	wantNoMask := "req=<UUID> ip=10.20.30.40:8080 cidr=192.168.1.0/24 v6=[2001:db8::1]:443 bare=fe80::1 cid=<HEX> ptr=<HEX> word=deadbeef"
	if resNoMask.Template != wantNoMask {
		t.Fatalf("MaskIPs=false:\ngot  %q\nwant %q", resNoMask.Template, wantNoMask)
	}
}

func TestNormalizeVersionsAndSemanticCodesPreserved(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Server: nginx/1.24.0", "Server: nginx/1.24.0"},
		{"Server: nginx/1.25.3", "Server: nginx/1.25.3"},
		{"release v1.27.3-rc.1+build.9", "release v1.27.3-rc.1+build.9"},
		{"HTTP/1.1 200 OK", "HTTP/1.1 200 OK"},
		{"HTTP/1.1 500 Internal Server Error", "HTTP/1.1 500 Internal Server Error"},
		{"HTTP 503 Service Unavailable", "HTTP 503 Service Unavailable"},
		{"status=503 latency=120ms", "status=503 latency=<DUR>"},
		{"status: 500 count=42", "status: 500 count=<NUM>"},
		{"exit_code=1 duration=3.5s", "exit_code=1 duration=<DUR>"},
		{"exit code 137 killed", "exit code 137 killed"},
		{"Exited (137) 5 minutes ago", "Exited (137) <DUR> ago"},
		{"Exited (0) 2 hours ago", "Exited (0) <DUR> ago"},
		{"signal 9 received", "signal 9 received"},
	}
	for _, tc := range cases {
		res := NormalizePreview([]byte(tc.in), DefaultNormalizeOptions(""))
		if res.Template != tc.want {
			t.Errorf("in=%q:\ngot  %q\nwant %q", tc.in, res.Template, tc.want)
		}
	}
}

func TestNormalizePIDDurationPctSizeAndIdentProtection(t *testing.T) {
	in := "Main PID: 12345 dev=/dev/sda1 disk=nvme0n1p1 nic=eth0 enc=utf8 utf-8 cpu=42.5% mem=512MiB disk2=4.2G dur=12m34s lat=123ms"
	res := NormalizePreview([]byte(in), DefaultNormalizeOptions(""))
	want := "Main PID: <PID> dev=/dev/sda1 disk=nvme0n1p1 nic=eth0 enc=utf8 utf-8 cpu=<PCT> mem=<SIZE> disk2=<SIZE> dur=<DUR> lat=<DUR>"
	if res.Template != want {
		t.Fatalf("got  %q\nwant %q", res.Template, want)
	}
	if len(res.Slots) != 5 {
		t.Fatalf("expected 5 numeric slots, got %d: %+v", len(res.Slots), res.Slots)
	}
	if res.Slots[0].Label != "cpu" || res.Slots[0].Unit != "%" || res.Slots[0].Value != 42.5 {
		t.Errorf("unexpected slot 0: %+v", res.Slots[0])
	}
	if res.Slots[1].Label != "mem" || res.Slots[1].Unit != "bytes" || res.Slots[1].Value != 512*1024*1024 {
		t.Errorf("unexpected slot 1: %+v", res.Slots[1])
	}
	if res.Slots[3].Label != "dur" || res.Slots[3].Unit != "ms" || res.Slots[3].Value != (12*60+34)*1000 {
		t.Errorf("unexpected slot 3: %+v", res.Slots[3])
	}
	if res.Slots[4].Label != "lat" || res.Slots[4].Unit != "ms" || res.Slots[4].Value != 123 {
		t.Errorf("unexpected slot 4: %+v", res.Slots[4])
	}
}

func TestNormalizeTruncationDropsIncompleteTrailingLine(t *testing.T) {
	raw := []byte("line1 val=10\nline2 val=20\nline3 val=30_partial")
	opts := DefaultNormalizeOptions("")
	opts.Truncated = true
	res := NormalizePreview(raw, opts)
	want := "line1 val=<NUM>\nline2 val=<NUM>"
	if res.Template != want {
		t.Fatalf("got %q, want %q", res.Template, want)
	}

	// Single 4 KiB line with NO newline must NOT be wiped to empty.
	longLine := bytes.Repeat([]byte("a"), MaxPreviewBytesPerStream)
	resSingle := NormalizePreview(longLine, opts)
	if len(resSingle.Template) != MaxLineBytes {
		t.Fatalf("expected capped single line len=%d, got %d", MaxLineBytes, len(resSingle.Template))
	}
	if !resSingle.Truncated {
		t.Fatalf("expected Truncated=true for oversized single line")
	}
}

func TestNormalizeJSONAndSemanticKeysAndHomogeneousArray(t *testing.T) {
	j1 := []byte(`{"z_val": 100, "exit_code": 0, "http_status": 200, "status": "healthy", "host": "web-01", "records": [{"msg": "timeout 120ms"}, {"msg": "timeout 150ms"}]}`)
	j2 := []byte(`{"host": "web-02", "status": "healthy", "records": [{"msg": "timeout 210ms"}], "http_status": 200, "exit_code": 0, "z_val": 250}`)
	j3 := []byte(`{"host": "web-03", "status": "healthy", "records": [{"msg": "timeout 210ms"}], "http_status": 500, "exit_code": 1, "z_val": 250}`)

	r1 := NormalizePreview(j1, DefaultNormalizeOptions("web-01"))
	r2 := NormalizePreview(j2, DefaultNormalizeOptions("web-02"))
	r3 := NormalizePreview(j3, DefaultNormalizeOptions("web-03"))

	if r1.Mode != PreviewModeJSON || r2.Mode != PreviewModeJSON {
		t.Fatalf("expected JSON mode, got %q and %q", r1.Mode, r2.Mode)
	}
	if r1.Template != r2.Template {
		t.Fatalf("expected identical templates:\nr1=%s\nr2=%s", r1.Template, r2.Template)
	}
	if r1.Template == r3.Template {
		t.Fatalf("expected semantic exit_code/http_status difference to keep templates distinct:\nr1=%s\nr3=%s", r1.Template, r3.Template)
	}
	if !strings.Contains(r3.Template, `"exit_code":1`) || !strings.Contains(r3.Template, `"http_status":500`) {
		t.Fatalf("expected literal semantic codes in r3 template: %s", r3.Template)
	}

	// Verify records.$len extracted with values 2 and 1.
	foundLen := false
	for _, s := range r1.Slots {
		if s.Label == "records.$len" && s.Value == 2 {
			foundLen = true
		}
	}
	if !foundLen {
		t.Fatalf("expected records.$len=2 in slots: %+v", r1.Slots)
	}
}

func TestNormalizeNDJSONOrderInvarianceAndTruncation(t *testing.T) {
	a := []byte("{\"ID\":\"a1b2c3d4e5f6\",\"Image\":\"nginx:1.25.3\",\"Names\":\"web\",\"Status\":\"Up 3 hours\"}\n" +
		"{\"ID\":\"11223344aabb\",\"Image\":\"redis:7.2.4\",\"Names\":\"cache\",\"Status\":\"Up 5 days\"}\n")
	b := []byte("{\"ID\":\"ffeeddcc1122\",\"Image\":\"redis:7.2.4\",\"Names\":\"cache\",\"Status\":\"Up 12 minutes\"}\n" +
		"{\"ID\":\"99887766aabb\",\"Image\":\"nginx:1.25.3\",\"Names\":\"web\",\"Status\":\"Up 1 hour\"}\n" +
		"{\"ID\":\"partial_trunc")

	mode := DetectStreamMode([]PreviewSample{
		{Data: a, TotalSize: uint64(len(a))},
		{Data: b, TotalSize: uint64(len(b) + 100)},
	})
	if mode != PreviewModeNDJSON {
		t.Fatalf("expected PreviewModeNDJSON, got %q", mode)
	}

	optsA := DefaultNormalizeOptions("h1")
	optsA.Mode = mode
	optsB := DefaultNormalizeOptions("h2")
	optsB.Mode = mode
	optsB.Truncated = true

	ra := NormalizePreview(a, optsA)
	rb := NormalizePreview(b, optsB)
	if ra.Template != rb.Template {
		t.Fatalf("NDJSON templates should match despite order and partial trailing line:\na=%s\nb=%s", ra.Template, rb.Template)
	}
}

func TestDetectStreamModeJSON4KiBBoundaryUnifiedToText(t *testing.T) {
	full := []byte(`{"heap_used": 1024, "heap_max": 4096}`)
	truncated := []byte(`{"heap_used": 2048, "heap_ma`)

	mode := DetectStreamMode([]PreviewSample{
		{Data: full, TotalSize: uint64(len(full))},
		{Data: truncated, TotalSize: 4200},
	})
	if mode != PreviewModeText {
		t.Fatalf("expected unified PreviewModeText when any host has truncated JSON, got %q", mode)
	}
}

func TestAdversarialNormalizationSafety(t *testing.T) {
	// 1. Deeply nested JSON (depth 50) must not panic and must fall back cleanly to text.
	deep := strings.Repeat(`{"a":`, 50) + "1" + strings.Repeat("}", 50)
	if isBoundedJSONObject(deep) {
		t.Fatalf("depth-50 JSON must fail bounded JSON check")
	}
	resDeep := NormalizePreview([]byte(deep), DefaultNormalizeOptions("h1"))
	if resDeep.Mode != PreviewModeText {
		t.Fatalf("expected text fallback for depth-50 JSON, got %q", resDeep.Mode)
	}

	// 2. Finite float invariant: 1e999 must never produce Inf/NaN slots.
	huge := []byte(`{"x": 1e999, "y": -1e999, "ok": 42}`)
	resHuge := NormalizePreview(huge, DefaultNormalizeOptions("h1"))
	for _, s := range resHuge.Slots {
		if math.IsNaN(s.Value) || math.IsInf(s.Value, 0) {
			t.Fatalf("non-finite slot emitted: %+v", s)
		}
	}
	resHugeText := NormalizePreview([]byte("val=1e999 huge=1e500 ok=7"), DefaultNormalizeOptions("h1"))
	for _, s := range resHugeText.Slots {
		if math.IsNaN(s.Value) || math.IsInf(s.Value, 0) {
			t.Fatalf("non-finite text slot emitted: %+v", s)
		}
	}

	// 3. Invalid UTF-8 and NUL bytes must produce valid UTF-8 templates and sanitized labels.
	bad := []byte("bad\x00\xff\xfe\x1b[31mkey\x7f=123\n")
	resBad := NormalizePreview(bad, DefaultNormalizeOptions("h1"))
	if !utf8.ValidString(resBad.Template) {
		t.Fatalf("template is not valid UTF-8: %q", resBad.Template)
	}
	for _, s := range resBad.Slots {
		assertCleanLabel(t, s.Label)
		assertCleanLabel(t, s.Unit)
	}

	// 4. SanitizeLabel control characters, whitespace collapse, and 64-byte UTF-8 boundary truncation.
	dirty := "  \x00\x01hello\t\n  world\x7f" + strings.Repeat("中", 30)
	clean := SanitizeLabel(dirty)
	assertCleanLabel(t, clean)
	if !strings.HasPrefix(clean, "hello world") {
		t.Fatalf("unexpected sanitized label: %q", clean)
	}
}

func assertCleanLabel(t *testing.T, s string) {
	t.Helper()
	if !utf8.ValidString(s) {
		t.Fatalf("label not valid UTF-8: %q", s)
	}
	if len(s) > MaxLabelBytes {
		t.Fatalf("label exceeds MaxLabelBytes (%d > %d): %q", len(s), MaxLabelBytes, s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			t.Fatalf("label contains control byte 0x%02x: %q", s[i], s)
		}
	}
}

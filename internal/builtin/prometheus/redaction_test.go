package prometheus

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/redact"
)

// realMask is the executor's masking function for the secrets and pii rules.
func realMask(t *testing.T) func(string) string {
	t.Helper()
	r, err := redact.New(&redact.Config{Builtin: []string{"secrets", "pii"}})
	if err != nil {
		t.Fatal(err)
	}
	return r.Line
}

// wrap marks every masked cell, so a test sees which cells reach the mask.
func wrap(s string) string { return "M(" + s + ")" }

func runMasked(t *testing.T, cfg Config, p Params, mask func(string) string) Result {
	t.Helper()
	r, err := RunRedacted(context.Background(), cfg, p, mask)
	if err != nil {
		t.Fatalf("RunRedacted: %v", err)
	}
	return r
}

// An 11-digit sample value is a phone number to the pii rule; values and times
// are numbers Prometheus guarantees, so they are never masked.
func TestNumericAndTimeColumnsAreNotMasked(t *testing.T) {
	useFixedClock(t)
	mask := realMask(t)
	if got := mask("16723996672"); !strings.Contains(got, "REDACTED") {
		t.Fatalf("precondition: redactor leaves %q", got)
	}
	big := "16723996672"
	f := serve(t, 200, vector(fmt.Sprintf(`{"metric":{"__name__":"m"},"value":[%d,"%s"]}`, fixedUnix, big)))
	r := runMasked(t, config("query", f), Params{Query: "m"}, mask)
	if want := "m\t2026-10-23T03:12:00Z\t" + big; lines(r.Stdout)[1] != want {
		t.Errorf("vector row = %q; want %q", lines(r.Stdout)[1], want)
	}

	f = serve(t, 200, success(fmt.Sprintf(`{"resultType":"scalar","result":[%d,"%s"]}`, fixedUnix, big)))
	r = runMasked(t, config("query", f), Params{Query: "1"}, mask)
	if want := "2026-10-23T03:12:00Z\t" + big; lines(r.Stdout)[1] != want {
		t.Errorf("scalar row = %q", lines(r.Stdout)[1])
	}

	matrix := success(fmt.Sprintf(`{"resultType":"matrix","result":[{"metric":{"__name__":"m"},"values":[[%d,"%s"],[%d,"%s"]]}]}`, fixedUnix-60, big, fixedUnix, big))
	f = serve(t, 200, matrix)
	r = runMasked(t, config("query_range", f), Params{Query: "m", Start: "now-1h", Step: time.Minute, HasStep: true}, mask)
	if want := "m\t2026-10-23T03:12:00Z\t" + big; lines(r.Stdout)[2] != want {
		t.Errorf("matrix row = %q", lines(r.Stdout)[2])
	}
	f = serve(t, 200, matrix)
	r = runMasked(t, config("query_range", f), Params{Query: "m", Start: "now-1h", Step: time.Minute, HasStep: true, Summary: true}, mask)
	if want := strings.Join([]string{"m", big, big, big, big}, "\t"); lines(r.Stdout)[1] != want {
		t.Errorf("summary row = %q; want %q", lines(r.Stdout)[1], want)
	}

	f = serve(t, 200, success(`{"alerts":[{"labels":{"alertname":"A"},"annotations":{},"state":"firing","activeAt":"2026-10-23T03:00:00Z","value":"`+big+`"}]}`))
	r = runMasked(t, config("alerts", f), Params{}, mask)
	if fields := strings.Split(lines(r.Stdout)[1], "\t"); fields[2] != "2026-10-23T03:00:00Z" || fields[3] != big {
		t.Errorf("alert row = %q", lines(r.Stdout)[1])
	}
}

func TestStringResultAndUnexpectedValuesAreMasked(t *testing.T) {
	useFixedClock(t)
	f := serve(t, 200, success(fmt.Sprintf(`{"resultType":"string","result":[%d,"16723996672"]}`, fixedUnix)))
	r := runMasked(t, config("query", f), Params{Query: `"x"`}, realMask(t))
	if strings.Contains(r.Stdout, "16723996672") {
		t.Errorf("string result not masked: %q", r.Stdout)
	}
	// A sample value that is not a number is text from the server: it is masked.
	f = serve(t, 200, vector(fmt.Sprintf(`{"metric":{"__name__":"m"},"value":[%d,"password=hunter2"]}`, fixedUnix)))
	r = runMasked(t, config("query", f), Params{Query: "m"}, wrap)
	if want := "M(m)\t2026-10-23T03:12:00Z\tM(password=hunter2)"; lines(r.Stdout)[1] != want {
		t.Errorf("row = %q; want %q", lines(r.Stdout)[1], want)
	}
}

func TestTextColumnsAreMasked(t *testing.T) {
	useFixedClock(t)
	f := serve(t, 200, success(`{"alerts":[{"labels":{"alertname":"A","job":"j"},"annotations":{"summary":"s"},"state":"firing","activeAt":"2026-10-23T03:00:00Z","value":"1"}]}`))
	r := runMasked(t, config("alerts", f), Params{}, wrap)
	fields := strings.Split(lines(r.Stdout)[1], "\t")
	if fields[0] != "M(A)" || fields[4] != `{M(alertname="A"),M(job="j")}` || fields[5] != "M(s)" {
		t.Errorf("alert row = %q", lines(r.Stdout)[1])
	}
	f = serve(t, 200, success(`{"activeTargets":[{"labels":{"instance":"i","job":"j"},"scrapeUrl":"http://i/metrics","lastError":"e","lastScrape":"2026-10-23T03:11:51Z","health":"up"}]}`))
	r = runMasked(t, config("targets", f), Params{}, wrap)
	if want := "M(j)\tM(i)\tM(up)\t2026-10-23T03:11:51Z\tM(e)\tM(http://i/metrics)"; lines(r.Stdout)[1] != want {
		t.Errorf("target row = %q", lines(r.Stdout)[1])
	}
}

// A rule that matches to the end of the line must not swallow later labels.
func TestLabelsAreMaskedOneByOne(t *testing.T) {
	useFixedClock(t)
	mask := realMask(t)
	f := serve(t, 200, vector(fmt.Sprintf(`{"metric":{"__name__":"up","msg":"password=hunter2","zone":"z"},"value":[%d,"1"]}`, fixedUnix)))
	r := runMasked(t, config("query", f), Params{Query: "up"}, mask)
	row := lines(r.Stdout)[1]
	if strings.Contains(row, "hunter2") || !strings.Contains(row, `zone="z"`) || !strings.Contains(row, "\t1") {
		t.Errorf("row = %q", row)
	}
	f = serve(t, 200, success(`[{"__name__":"up","msg":"password=hunter2","zone":"z"}]`))
	r = runMasked(t, config("series", f), Params{Match: []string{"up"}}, mask)
	if row := lines(r.Stdout)[1]; strings.Contains(row, "hunter2") || !strings.Contains(row, `zone="z"`) {
		t.Errorf("series row = %q", row)
	}
	f = serve(t, 200, vector(fmt.Sprintf(`{"metric":{"__name__":"up","job":"a"},"value":[%d,"1"]}`, fixedUnix)))
	r = runMasked(t, config("query", f), Params{Query: "up"}, wrap)
	if want := `M(up){M(job="a")}` + "\t2026-10-23T03:12:00Z\t1"; lines(r.Stdout)[1] != want {
		t.Errorf("row = %q; want %q", lines(r.Stdout)[1], want)
	}
}

// The label set of a series is masked once, however many points it has.
func TestLabelSetIsMaskedOncePerSeries(t *testing.T) {
	useFixedClock(t)
	var points []string
	for i := 0; i < 200; i++ {
		points = append(points, fmt.Sprintf(`[%d,"%d"]`, fixedUnix-i*60, i))
	}
	f := serve(t, 200, success(`{"resultType":"matrix","result":[{"metric":{"__name__":"m","a":"1","b":"2"},"values":[`+strings.Join(points, ",")+`]}]}`))
	calls := 0
	mask := func(s string) string { calls++; return s }
	cfg := config("query", f)
	r := runMasked(t, cfg, Params{Query: "m[200m]"}, mask)
	if len(lines(r.Stdout)) != 201 {
		t.Fatalf("rows = %d", len(lines(r.Stdout)))
	}
	if calls > 3 { // metric name and two labels
		t.Errorf("mask called %d times for one series of 200 points", calls)
	}
}

func TestLabelValuesAreMaskedWithTheirLabelName(t *testing.T) {
	useFixedClock(t)
	mask := realMask(t)
	if bare := mask("hunter2"); bare != "hunter2" {
		t.Fatalf("precondition: bare value is masked: %q", bare)
	}
	f := serve(t, 200, success(`["hunter2","plain"]`))
	r := runMasked(t, config("label_values", f), Params{Label: "api_token"}, mask)
	if out := r.Stdout; strings.Contains(out, "hunter2") || !strings.Contains(out, "REDACTED") {
		t.Errorf("stdout = %q", out)
	}
	// With a mask that sees the context, an unchanged pair prints the bare value.
	seen := []string{}
	f = serve(t, 200, success(`["a"]`))
	runMasked(t, config("label_values", f), Params{Label: "job"}, func(s string) string { seen = append(seen, s); return s })
	if len(seen) != 1 || seen[0] != `job="a"` {
		t.Errorf("mask saw %q", seen)
	}
}

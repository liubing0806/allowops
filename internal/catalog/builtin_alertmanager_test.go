package catalog

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/params"
)

func alertmanagerAction(config map[string]any) Action {
	return Action{Name: "alertmanager_alerts", Description: "alerts", Risk: "read", Builtin: "alertmanager_alerts", BuiltinConfig: config, Timeout: "15s", MaxOutput: 64 << 10}
}

func TestAlertmanagerRegistered(t *testing.T) {
	if _, ok := Builtins["alertmanager_alerts"]; !ok {
		t.Fatal("alertmanager_alerts is not registered")
	}
}

func TestAlertmanagerParameters(t *testing.T) {
	a := alertmanagerAction(map[string]any{"address": "http://127.0.0.1:9093"})
	defs, err := ParameterDefinitions(a)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]params.Definition{
		"filter":    {Type: params.StringArray, MaxLen: 256, MaxItems: 10, Optional: true},
		"active":    {Type: params.Bool, Default: true},
		"silenced":  {Type: params.Bool, Default: false},
		"inhibited": {Type: params.Bool, Default: false},
	}
	if len(defs) != len(want) {
		t.Fatalf("definitions = %v", defs)
	}
	for name, w := range want {
		g := defs[name]
		if g.Type != w.Type || g.MaxLen != w.MaxLen || g.MaxItems != w.MaxItems || g.Optional != w.Optional || !reflect.DeepEqual(g.Default, w.Default) {
			t.Errorf("%s = %+v, want %+v", name, g, w)
		}
		if g.Description == "" {
			t.Errorf("%s has no description", name)
		}
	}
	parsed, err := params.Parse(defs, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if parsed["active"] != true || parsed["silenced"] != false || parsed["inhibited"] != false {
		t.Fatalf("defaults = %v", parsed)
	}
	if _, err := params.JSONSchema(defs); err != nil {
		t.Fatal(err)
	}
	a.Params = map[string]params.Definition{"filter": {Type: params.StringArray, MaxLen: 64}}
	if _, err := ValidateAction(a); err != nil {
		t.Fatalf("tightening filter length: %v", err)
	}
	a.Params = map[string]params.Definition{"filter": {Type: params.StringArray, MaxLen: 257}}
	if _, err := ValidateAction(a); err == nil {
		t.Fatal("widening filter length accepted")
	}
	a.Params = map[string]params.Definition{"unknown": {Type: params.String, Description: "x"}}
	if _, err := ValidateAction(a); err == nil {
		t.Fatal("unknown parameter accepted")
	}
}

func TestAlertmanagerConfigValidation(t *testing.T) {
	base := func() map[string]any { return map[string]any{"address": "http://127.0.0.1:9093"} }
	with := func(key string, value any) map[string]any { c := base(); c[key] = value; return c }
	ok := map[string]map[string]any{
		"minimal":                  base(),
		"https with ca":            {"address": "https://am.example.com/prefix", "ca_file": "/etc/ssl/am-ca.pem"},
		"timeout at max":           with("timeout", "30s"),
		"timeout narrow":           with("timeout", "50ms"),
		"max_alerts at max":        with("max_alerts", 1000),
		"max_response_bytes max":   with("max_response_bytes", "16MB"),
		"max_response_bytes bytes": with("max_response_bytes", 1024),
	}
	for name, config := range ok {
		if _, err := ValidateAction(alertmanagerAction(config)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]map[string]any{
		"no config":               nil,
		"no address":              {},
		"unknown field":           with("unexpected", true),
		"userinfo":                with("address", "http://user:pw@127.0.0.1:9093"),
		"query":                   with("address", "http://127.0.0.1:9093/?x=1"),
		"relative credential":     with("credential", "am.json"),
		"ca_file over http":       with("ca_file", "/etc/ssl/am-ca.pem"),
		"timeout above max":       with("timeout", "31s"),
		"timeout not a duration":  with("timeout", "soon"),
		"timeout not a string":    with("timeout", 5),
		"max_alerts above max":    with("max_alerts", 1001),
		"max_alerts negative":     with("max_alerts", -1),
		"max_alerts not a number": with("max_alerts", "many"),
		"response above max":      with("max_response_bytes", "17MB"),
		"response bytes above":    with("max_response_bytes", fmt.Sprint(16<<20+1)),
		"response not a size":     with("max_response_bytes", "big"),
	}
	for name, config := range bad {
		if _, err := ValidateAction(alertmanagerAction(config)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAlertmanagerCredentialRequiresRootExec(t *testing.T) {
	config := map[string]any{"address": "http://127.0.0.1:9093", "credential": "/etc/allowops/credentials/alertmanager.json"}
	for _, tc := range []struct {
		runAs string
		ok    bool
	}{{"", false}, {"root", true}, {"app", false}} {
		a := alertmanagerAction(config)
		a.RunAs = tc.runAs
		_, err := ValidateAction(a)
		if (err == nil) != tc.ok {
			t.Errorf("credential with run_as=%q: err=%v, want ok=%v", tc.runAs, err, tc.ok)
		}
		if err != nil && !strings.Contains(err.Error(), "run_as: root") {
			t.Errorf("error must name the requirement: %v", err)
		}
	}
	// Without a credential no privilege is needed and none is demanded.
	a := alertmanagerAction(map[string]any{"address": "http://127.0.0.1:9093"})
	if _, err := ValidateAction(a); err != nil || a.RequiresExec() {
		t.Fatalf("no credential: err=%v requires_exec=%v", err, a.RequiresExec())
	}
	a.RunAs = "root"
	if _, err := ValidateAction(a); err != nil || !a.RequiresExec() {
		t.Fatalf("run_as root without credential: err=%v requires_exec=%v", err, a.RequiresExec())
	}
}

func TestAlertmanagerRunThroughAdapter(t *testing.T) {
	var query string
	body := `[{"startsAt":"2026-10-23T02:00:00Z","status":{"state":"active"},"labels":{"alertname":"A","severity":"warning"},"annotations":{"summary":"password=hunter2"}},
	{"startsAt":"2026-10-23T03:00:00Z","status":{"state":"active"},"labels":{"alertname":"B"}}]`
	status := 200
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	defer server.Close()
	config := map[string]any{"address": server.URL, "max_alerts": 1}
	handler, registered := Builtins["alertmanager_alerts"]
	if !registered {
		t.Fatal("alertmanager_alerts is not registered")
	}
	values := map[string]any{"filter": []string{`alertname="A"`}, "active": true, "silenced": true, "inhibited": false}
	mask := func(s string) string { return strings.ReplaceAll(s, "hunter2", "[REDACTED]") }

	r, err := handler.(RedactingBuiltinHandler).RunRedacted(context.Background(), config, values, mask)
	if err != nil || r.ExitCode != 0 || !r.ResourceLimited {
		t.Fatalf("result = %+v, err = %v", r, err)
	}
	if strings.Contains(r.Stdout, "hunter2") || !strings.Contains(r.Stdout, "[REDACTED]") || strings.Count(r.Stdout, "\n") != 1 {
		t.Fatalf("stdout = %q", r.Stdout)
	}
	if !strings.Contains(r.Stderr, "1 of 2") {
		t.Fatalf("stderr = %q", r.Stderr)
	}
	for _, want := range []string{"active=true", "silenced=true", "inhibited=false", "filter=alertname%3D%22A%22"} {
		if !strings.Contains(query, want) {
			t.Errorf("query %q lacks %s", query, want)
		}
	}
	// Run is the unredacted entry point.
	raw, err := handler.Run(context.Background(), config, values)
	if err != nil || !strings.Contains(raw.Stdout, "hunter2") {
		t.Fatalf("Run = %+v, %v", raw, err)
	}

	status, body = 400, "parse error"
	r, err = handler.Run(context.Background(), config, values)
	if err != nil || r.ExitCode != 1 || !strings.Contains(r.Stderr, "HTTP 400") || r.Stdout != "" {
		t.Fatalf("error status: %+v, %v", r, err)
	}

	if _, err := handler.Run(context.Background(), map[string]any{"address": server.URL, "max_alerts": 1001}, values); err == nil {
		t.Fatal("widened config reached the server")
	}
}

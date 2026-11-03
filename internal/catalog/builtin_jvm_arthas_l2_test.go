package catalog

import (
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/arthas"
	"github.com/liubing0806/allowops/internal/builtin/jvmarthas"
	"github.com/liubing0806/allowops/internal/params"
	"github.com/liubing0806/allowops/internal/redact"
)

var l2Commands = []string{"watch", "trace", "stack", "monitor", "jad"}

func TestJVMArthasL2ConfigMapsTheL2Keys(t *testing.T) {
	a := jvmArthasAction("watch")
	maps.Copy(a.BuiltinConfig, map[string]any{
		"class_prefixes": []any{"com.example."}, "enhance_duration": "10s", "max_methods": 2, "object_size_limit": "16KB",
		"checks": map[string]any{"max_cpu_percent": 30},
	})
	cfg, err := jvmArthasConfig(a.BuiltinConfig)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.ClassPrefixes, []string{"com.example."}) || cfg.EnhanceDuration != 10*time.Second || cfg.MaxMethods != 2 ||
		cfg.ObjectSizeLimit != 16<<10 || cfg.Checks.MaxCPUPercent != 30 {
		t.Errorf("config = %+v", cfg)
	}
}

func TestJVMArthasL2ConfigRejects(t *testing.T) {
	cases := map[string]struct {
		command string
		mutate  func(map[string]any)
	}{
		"no class prefixes":           {"watch", func(c map[string]any) { delete(c, "class_prefixes") }},
		"jad without class prefixes":  {"jad", func(c map[string]any) { c["class_prefixes"] = []any{} }},
		"prefix without a dot":        {"trace", func(c map[string]any) { c["class_prefixes"] = []any{"com.example"} }},
		"wildcard prefix":             {"stack", func(c map[string]any) { c["class_prefixes"] = []any{"com.*."} }},
		"forbidden prefix":            {"monitor", func(c map[string]any) { c["class_prefixes"] = []any{"java."} }},
		"Arthas prefix":               {"jad", func(c map[string]any) { c["class_prefixes"] = []any{"com.alibaba.arthas."} }},
		"prefix not a string":         {"watch", func(c map[string]any) { c["class_prefixes"] = []any{1} }},
		"enhancement above 30s":       {"watch", func(c map[string]any) { c["enhance_duration"] = "31s" }},
		"enhancement text":            {"trace", func(c map[string]any) { c["enhance_duration"] = "long" }},
		"enhancement for jad":         {"jad", func(c map[string]any) { c["enhance_duration"] = "10s" }},
		"monitor for one second":      {"monitor", func(c map[string]any) { c["enhance_duration"] = "1s" }},
		"more methods":                {"stack", func(c map[string]any) { c["max_methods"] = 6 }},
		"methods for jad":             {"jad", func(c map[string]any) { c["max_methods"] = 1 }},
		"object size above 64KB":      {"watch", func(c map[string]any) { c["object_size_limit"] = "65KB" }},
		"object size of a terabyte":   {"watch", func(c map[string]any) { c["object_size_limit"] = "1048576GB" }},
		"object size below 256 bytes": {"watch", func(c map[string]any) { c["object_size_limit"] = 255 }},
		"object size for trace":       {"trace", func(c map[string]any) { c["object_size_limit"] = "8KB" }},
		"cpu share above 50":          {"watch", func(c map[string]any) { c["checks"] = map[string]any{"max_cpu_percent": 51} }},
		"unknown L2 key":              {"watch", func(c map[string]any) { c["express"] = "params" }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			a := jvmArthasAction(tc.command)
			tc.mutate(a.BuiltinConfig)
			if _, err := ValidateAction(a); err == nil {
				t.Errorf("accepted %v", a.BuiltinConfig)
			}
		})
	}
}

func TestJVMArthasL2ActionFields(t *testing.T) {
	cases := map[string]struct {
		command string
		mutate  func(*Action)
		want    string
	}{
		"no redaction":            {"watch", func(a *Action) { a.Redact = nil }, "redact.builtin with secrets and pii"},
		"secrets only":            {"trace", func(a *Action) { a.Redact = &redact.Config{Builtin: []string{"secrets"}} }, "secrets and pii"},
		"pii only":                {"jad", func(a *Action) { a.Redact = &redact.Config{Builtin: []string{"pii"}} }, "secrets and pii"},
		"builtins off":            {"stack", func(a *Action) { a.Redact = &redact.Config{Builtin: []string{}} }, "secrets and pii"},
		"timeout below 90s":       {"watch", func(a *Action) { a.Timeout = "89s" }, "timeout of at least 1m30s"},
		"jad timeout below 70s":   {"jad", func(a *Action) { a.Timeout = "69s" }, "timeout of at least 1m10s"},
		"jad with a longer exec":  {"jad", func(a *Action) { a.BuiltinConfig["exec_timeout"] = "40s" }, "timeout of at least 1m40s"},
		"monitor timeout of 30s":  {"monitor", func(a *Action) { a.Timeout = "30s" }, "timeout of at least"},
		"risk read":               {"watch", func(a *Action) { a.Risk = "read" }, "risk: write"},
		"two targets":             {"jad", func(a *Action) { two := 2; a.MaxTargets = &two }, "max_targets: 1"},
		"shorter but still below": {"trace", func(a *Action) { a.BuiltinConfig["enhance_duration"] = "10s"; a.Timeout = "69s" }, "timeout of at least 1m10s"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			a := jvmArthasAction(tc.command)
			tc.mutate(&a)
			if _, err := ValidateAction(a); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ValidateAction() = %v; want an error mentioning %q", err, tc.want)
			}
		})
	}
	for _, command := range l2Commands {
		a := jvmArthasAction(command)
		a.Redact = &redact.Config{Builtin: []string{"pii", "secrets"}, Custom: []redact.Rule{{Name: "order", Regex: `ORD-[0-9]+`}}}
		if _, err := ValidateAction(a); err != nil {
			t.Errorf("%s: %v", command, err)
		}
	}
	a := jvmArthasAction("trace")
	a.BuiltinConfig["enhance_duration"] = "10s"
	a.Timeout = "70s"
	if _, err := ValidateAction(a); err != nil {
		t.Errorf("trace with a 10s enhancement and a 70s timeout: %v", err)
	}
	// The L1 actions keep their own rules.
	l1 := jvmArthasAction("dashboard")
	l1.Timeout = "20s"
	if _, err := ValidateAction(l1); err != nil {
		t.Errorf("dashboard: %v", err)
	}
}

func TestJVMArthasMonitorCycleFollowsTheEnhancement(t *testing.T) {
	a := jvmArthasAction("monitor")
	a.BuiltinConfig["enhance_duration"] = "10s"
	defs, err := ParameterDefinitions(a)
	if err != nil {
		t.Fatal(err)
	}
	if defs["cycle"].Max != int64(9) {
		t.Errorf("cycle = %+v", defs["cycle"])
	}
	a.BuiltinConfig["enhance_duration"] = "2s"
	if defs, err := ParameterDefinitions(a); err != nil || defs["cycle"].Max != int64(1) {
		t.Errorf("2s: %+v, %v", defs["cycle"], err)
	}
}

// The values the parameter layer lets through are accepted by arthas.Build with the policy of
// the action, and every hostile value is rejected by the parameters or by Build.
func TestJVMArthasL2ParameterValuesCannotCarryAnotherCommand(t *testing.T) {
	policy := arthas.Policy{ClassPrefixes: []string{"com.example.", "demo."}}
	build := func(command string, values map[string]any) error {
		req := arthas.Request{Kind: arthas.Kind(command)}
		req.Class, _ = values["class"].(string)
		req.Method, _ = values["method"].(string)
		req.Express, _ = values["express"].(string)
		if n, ok := values["expand"].(int64); ok {
			req.Expand = int(n)
		}
		if n, ok := values["count"].(int64); ok {
			req.Count = int(n)
		}
		req.MinCost, _ = values["min_cost_ms"].(int64)
		if n, ok := values["cycle"].(int64); ok {
			req.Cycle = int(n)
		}
		_, err := arthas.Build(req, policy)
		return err
	}
	good := map[string]map[string]any{
		"watch":   {"class": "demo.HotService", "method": "work", "express": "params,returnObj,throwExp", "expand": int64(2), "count": int64(5), "min_cost_ms": int64(3600000)},
		"trace":   {"class": "com.example.Api$Inner", "method": "lambda$handle$0"},
		"stack":   {"class": "demo.HotService", "method": "work", "min_cost_ms": int64(1)},
		"monitor": {"class": "demo.HotService", "method": "work", "count": int64(2), "cycle": int64(14)},
		"jad":     {"class": "demo.HotService"},
	}
	hostile := []string{
		"", " ", "demo.A;reset", "demo.A|stop", "demo.A>x", "demo.A\nstop", "demo.A\r\nstop", "demo.A'x", `demo.A"x`, "demo.*", "demo.A*", "demo.A?",
		"demo.A -E", "-E", "demo.A --classLoader x", "#cost>0", "@java.lang.Runtime@getRuntime().exec('id')", "{params}", "demo.A{params}",
		"demo.A`id`", "demo.A$(id)", "demo.A,demo.B", "demo.A demo.B", "demo..A", ".demo.A", "demo.A.", "ｄemo.A", strings.Repeat("a", 256),
	}
	for command, values := range good {
		defs, err := ParameterDefinitions(jvmArthasAction(command))
		if err != nil {
			t.Fatal(err)
		}
		in := maps.Clone(values)
		in["target"] = "api"
		parsed, err := params.Parse(defs, in)
		if err != nil {
			t.Errorf("%s %v: %v", command, values, err)
			continue
		}
		if err := build(command, parsed); err != nil {
			t.Errorf("%s %v passed the parameters but not Build: %v", command, values, err)
		}
		for _, field := range []string{"class", "method"} {
			for _, h := range hostile {
				in := maps.Clone(in)
				in[field] = h
				parsed, err := params.Parse(defs, in)
				if err == nil && build(command, parsed) == nil && !(command == "jad" && field == "method" && h == "") {
					t.Errorf("%s accepted %s %q", command, field, h)
				}
			}
		}
		// Classes outside the prefixes or in a forbidden package pass the parameters and fail in Build.
		for _, class := range []string{"java.lang.String", "sun.misc.Unsafe", "com.taobao.arthas.core.Main", "org.example.A"} {
			in := maps.Clone(in)
			in["class"] = class
			parsed, err := params.Parse(defs, in)
			if err == nil && build(command, parsed) == nil {
				t.Errorf("%s accepted class %s", command, class)
			}
		}
	}
	defs, _ := ParameterDefinitions(jvmArthasAction("watch"))
	for _, express := range []string{"target", "params,target", "params.length", "#cost", "@java.lang.System@exit(1)", "params returnObj", "{params}", "params;reset"} {
		if _, err := params.Parse(defs, map[string]any{"target": "api", "class": "demo.A", "method": "run", "express": express}); err == nil {
			t.Errorf("express %q was accepted", express)
		}
	}
	for name, values := range map[string]map[string]any{
		"count 0": {"count": int64(0)}, "count 6": {"count": int64(6)}, "expand 3": {"expand": int64(3)}, "expand 0": {"expand": int64(0)},
		"min cost 0": {"min_cost_ms": int64(0)}, "min cost too high": {"min_cost_ms": int64(3600001)}, "count text": {"count": "1; reset"},
	} {
		in := map[string]any{"target": "api", "class": "demo.A", "method": "run"}
		maps.Copy(in, values)
		if _, err := params.Parse(defs, in); err == nil {
			t.Errorf("watch accepted %s", name)
		}
	}
	monitor, _ := ParameterDefinitions(jvmArthasAction("monitor"))
	for _, cycle := range []int64{0, 30, -1} {
		if _, err := params.Parse(monitor, map[string]any{"target": "api", "class": "demo.A", "method": "run", "cycle": cycle}); err == nil {
			t.Errorf("monitor accepted cycle %d", cycle)
		}
	}
	// count × cycle reaching the enhancement time passes the parameters and fails in Build.
	parsed, err := params.Parse(monitor, map[string]any{"target": "api", "class": "demo.A", "method": "run", "count": int64(5), "cycle": int64(6)})
	if err != nil || build("monitor", parsed) == nil {
		t.Errorf("monitor -n 5 -c 6 within 30s: %v", err)
	}
}

func TestJVMArthasL2ConfigIsPassedToTheHandler(t *testing.T) {
	a := jvmArthasAction("watch")
	a.BuiltinConfig["enhance_duration"] = "5s"
	cfg, err := jvmArthasConfig(a.BuiltinConfig)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Effective().EnhanceDuration != 5*time.Second || cfg.Effective().ObjectSizeLimit != arthas.DefaultObjectSizeLimit ||
		cfg.Effective().Checks.MaxCPUPercent != jvmarthas.DefaultMaxCPUPercent {
		t.Errorf("effective = %+v", cfg.Effective())
	}
}

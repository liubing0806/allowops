package catalog

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/arthas"
	"github.com/liubing0806/allowops/internal/builtin/jvmarthas"
	"github.com/liubing0806/allowops/internal/jvmtarget"
	"github.com/liubing0806/allowops/internal/params"
	"github.com/liubing0806/allowops/internal/redact"
)

const arthasSum = "b5bf8765c7621849889fb6522a296fa177ceb3f5c2c2b6d9f631d761ca9c04f9"

func arthasSums() map[string]any {
	m := map[string]any{}
	for _, name := range jvmarthas.FileNames {
		m[name] = arthasSum
	}
	return m
}

func jvmArthasAction(command string) Action {
	one, no := 1, false
	cfg := map[string]any{
		"command": command,
		"targets": map[string]any{
			"web": map[string]any{"container": "shop-web", "main_class": "com.example.shop.Main"},
			"api": map[string]any{"systemd_unit": "api.service"},
		},
		"sha256": arthasSums(),
	}
	if command == "sysprop" {
		cfg["sysprop_keys"] = []any{"user.timezone", "java.version"}
	}
	a := Action{
		Name: "jvm_arthas_" + command, Description: "Arthas " + command, Risk: "write", RunAs: "root", Idempotent: &no,
		Builtin: "jvm_arthas", BuiltinConfig: cfg, Timeout: "90s", MaxOutput: 65536, BatchSize: 1, MaxFailures: &one, MaxTargets: &one,
	}
	if arthas.Kind(command).Level() == 2 {
		cfg["class_prefixes"] = []any{"com.example.", "demo."}
		a.Redact = &redact.Config{Builtin: []string{"secrets", "pii"}}
	}
	return a
}

func TestJVMArthasIsRegisteredForEveryCommand(t *testing.T) {
	if _, ok := Builtins["jvm_arthas"]; !ok {
		t.Fatal("jvm_arthas is not registered")
	}
	for _, kind := range arthas.Kinds() {
		if _, err := ValidateAction(jvmArthasAction(string(kind))); err != nil {
			t.Errorf("%s: %v", kind, err)
		}
	}
}

func TestJVMArthasConfigRejects(t *testing.T) {
	longKeys := make([]any, 65)
	for i := range longKeys {
		longKeys[i] = "key" + strings.Repeat("a", i)
	}
	health := func(extra map[string]any) map[string]any {
		h := map[string]any{"url": "http://127.0.0.1:8080/health", "allowed_prefixes": []any{"http://127.0.0.1:8080/"}}
		maps.Copy(h, extra)
		return map[string]any{"health_check": h}
	}
	cases := map[string]func(map[string]any){
		"unknown field":                func(c map[string]any) { c["pid"] = 1 },
		"unknown check":                func(c map[string]any) { c["checks"] = map[string]any{"max_pid": 1} },
		"unknown guard field":          func(c map[string]any) { c["guard"] = map[string]any{"kill": true} },
		"unknown command":              func(c map[string]any) { c["command"] = "ognl" },
		"watch without class prefixes": func(c map[string]any) { c["command"] = "watch" },
		"class prefixes for L1":        func(c map[string]any) { c["class_prefixes"] = []any{"com.example."} },
		"cpu share for L1":             func(c map[string]any) { c["checks"] = map[string]any{"max_cpu_percent": 10} },
		"logger is paused":             func(c map[string]any) { c["command"] = "logger" },
		"missing command":              func(c map[string]any) { delete(c, "command") },
		"command not a string":         func(c map[string]any) { c["command"] = 1 },
		"missing targets":              func(c map[string]any) { delete(c, "targets") },
		"pid in a target": func(c map[string]any) {
			c["targets"] = map[string]any{"api": map[string]any{"systemd_unit": "api.service", "pid": 1}}
		},
		"missing sha256":      func(c map[string]any) { delete(c, "sha256") },
		"missing one sum":     func(c map[string]any) { delete(c["sha256"].(map[string]any), "logback.xml") },
		"extra sum":           func(c map[string]any) { c["sha256"].(map[string]any)["arthas-boot.jar"] = arthasSum },
		"short sum":           func(c map[string]any) { c["sha256"].(map[string]any)["arthas-core.jar"] = arthasSum[:10] },
		"relative dir":        func(c map[string]any) { c["arthas_dir"] = "arthas" },
		"dir with ..":         func(c map[string]any) { c["arthas_dir"] = "/opt/../etc" },
		"dir with semicolon":  func(c map[string]any) { c["arthas_dir"] = "/opt/a;b" },
		"port below 1024":     func(c map[string]any) { c["http_port_min"], c["http_port_max"] = 80, 90 },
		"port range reversed": func(c map[string]any) { c["http_port_min"], c["http_port_max"] = 20000, 19000 },
		"single port bound":   func(c map[string]any) { c["http_port_min"] = 20000 },
		"exec timeout 61s":    func(c map[string]any) { c["exec_timeout"] = "61s" },
		"exec timeout text":   func(c map[string]any) { c["exec_timeout"] = "soon" },
		"keys for dashboard":  func(c map[string]any) { c["sysprop_keys"] = []any{"java.version"} },
		"sysprop without keys": func(c map[string]any) {
			c["command"] = "sysprop"
			delete(c, "sysprop_keys")
		},
		"sysprop key with space": func(c map[string]any) { c["command"] = "sysprop"; c["sysprop_keys"] = []any{"a b"} },
		"too many sysprop keys":  func(c map[string]any) { c["command"] = "sysprop"; c["sysprop_keys"] = longKeys },
		"memory headroom below default": func(c map[string]any) {
			c["checks"] = map[string]any{"min_memory_headroom": "128MB"}
		},
		"metaspace headroom below default": func(c map[string]any) {
			c["checks"] = map[string]any{"min_metaspace_headroom": "32MB"}
		},
		"size text":                  func(c map[string]any) { c["checks"] = map[string]any{"min_memory_headroom": "lots"} },
		"more attaches than allowed": func(c map[string]any) { c["checks"] = map[string]any{"max_attaches": 6} },
		"attach interval below default": func(c map[string]any) {
			c["checks"] = map[string]any{"min_attach_interval": "30s"}
		},
		"interval text": func(c map[string]any) { c["checks"] = map[string]any{"min_attach_interval": "later"} },
		"more blocking threads": func(c map[string]any) {
			c["checks"] = map[string]any{"max_blocking_threads": 1001}
		},
		"old gen above default": func(c map[string]any) { c["checks"] = map[string]any{"max_old_gen_percent": 86} },
		"old gen above 100":     func(c map[string]any) { c["checks"] = map[string]any{"max_old_gen_percent": 101} },
		"full gc below default": func(c map[string]any) { c["checks"] = map[string]any{"no_full_gc_within": "30s"} },
		"negative full gc":      func(c map[string]any) { c["checks"] = map[string]any{"no_full_gc_within": "-1s"} },
		"negative cpu":          func(c map[string]any) { c["guard"] = map[string]any{"max_cpu_percent": -1} },
		"gc time above 100":     func(c map[string]any) { c["guard"] = map[string]any{"max_gc_time_percent": 101} },
		"settle above a minute": func(c map[string]any) { c["guard"] = map[string]any{"settle": "61s"} },
		"health without prefixes": func(c map[string]any) {
			c["guard"] = map[string]any{"health_check": map[string]any{"url": "http://127.0.0.1:8080/health"}}
		},
		"health outside prefixes": func(c map[string]any) {
			c["guard"] = health(map[string]any{"url": "http://127.0.0.1:9090/health"})
		},
		"health with credentials": func(c map[string]any) {
			c["guard"] = health(map[string]any{"url": "http://user:pw@127.0.0.1:8080/health"})
		},
		"health timeout 11s":   func(c map[string]any) { c["guard"] = health(map[string]any{"timeout": "11s"}) },
		"health failures 11":   func(c map[string]any) { c["guard"] = health(map[string]any{"max_failures": 11}) },
		"health unknown field": func(c map[string]any) { c["guard"] = health(map[string]any{"headers": map[string]any{"x": "y"}}) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := jvmArthasAction("dashboard")
			mutate(a.BuiltinConfig)
			if _, err := ValidateAction(a); err == nil {
				t.Errorf("accepted %v", a.BuiltinConfig)
			}
		})
	}
}

func fullArthasConfig() map[string]any {
	a := jvmArthasAction("sysprop")
	maps.Copy(a.BuiltinConfig, map[string]any{
		"arthas_dir": "/opt/arthas-minlog", "http_port_min": 20000, "http_port_max": 20010, "exec_timeout": "20s",
		"checks": map[string]any{
			"min_memory_headroom": "512MB", "min_metaspace_headroom": 128 << 20, "max_attaches": 3, "min_attach_interval": "5m",
			"max_blocking_threads": 100, "max_old_gen_percent": 80, "no_full_gc_within": "2m",
		},
		"guard": map[string]any{
			"max_cpu_percent": 300, "max_gc_time_percent": 50, "max_gc_per_second": 5, "settle": "8s",
			"health_check": map[string]any{
				"url": "http://127.0.0.1:8080/health", "allowed_prefixes": []any{"http://127.0.0.1:8080/"},
				"timeout": "3s", "max_failures": 4, "max_latency": "1500ms",
			},
		},
	})
	return a.BuiltinConfig
}

func TestJVMArthasConfigAcceptsAndMapsTighterValues(t *testing.T) {
	cfg, err := jvmArthasConfig(fullArthasConfig())
	if err != nil {
		t.Fatal(err)
	}
	want := jvmarthas.Config{
		Command: arthas.KindSysprop,
		Targets: map[string]jvmtarget.Target{
			"api": {Name: "api", SystemdUnit: "api.service"},
			"web": {Name: "web", Container: "shop-web", MainClass: "com.example.shop.Main"},
		},
		ArthasDir: "/opt/arthas-minlog", HTTPPortMin: 20000, HTTPPortMax: 20010, ExecTimeout: 20 * time.Second,
		SyspropKeys: []string{"user.timezone", "java.version"},
		Checks: jvmarthas.Checks{
			MinMemoryHeadroom: 512 << 20, MinMetaspaceHeadroom: 128 << 20, MaxAttaches: 3, MinAttachInterval: 5 * time.Minute,
			MaxBlockingThreads: 100, MaxOldGenPercent: 80, NoFullGCWithin: 2 * time.Minute,
		},
		Guard: jvmarthas.Guard{
			MaxCPUPercent: 300, MaxGCTimePercent: 50, MaxGCPerSecond: 5, Settle: 8 * time.Second,
			Health: &jvmarthas.HealthCheck{
				URL: "http://127.0.0.1:8080/health", AllowedPrefixes: []string{"http://127.0.0.1:8080/"},
				Timeout: 3 * time.Second, MaxFailures: 4, MaxLatency: 1500 * time.Millisecond,
			},
		},
	}
	got := cfg
	got.SHA256 = nil
	if !reflect.DeepEqual(got, want) {
		t.Errorf("config = %+v\nwant     %+v", got, want)
	}
	if len(cfg.SHA256) != len(jvmarthas.FileNames) || cfg.SHA256["arthas-core.jar"] != arthasSum {
		t.Errorf("sha256 = %v", cfg.SHA256)
	}
	a := jvmArthasAction("sysprop")
	a.BuiltinConfig = fullArthasConfig()
	if _, err := ValidateAction(a); err != nil {
		t.Errorf("tighter config: %v", err)
	}
}

func TestJVMArthasActionFieldRules(t *testing.T) {
	two, zero, one := 2, 0, 1
	yes := true
	cases := map[string]func(*Action){
		"no run_as":          func(a *Action) { a.RunAs = "" },
		"run_as a user":      func(a *Action) { a.RunAs = "app" },
		"risk read":          func(a *Action) { a.Risk = "read" },
		"risk destructive":   func(a *Action) { a.Risk = "destructive" },
		"idempotent unset":   func(a *Action) { a.Idempotent = nil },
		"idempotent":         func(a *Action) { a.Idempotent = &yes },
		"batch size unset":   func(a *Action) { a.BatchSize = 0 },
		"batch size 2":       func(a *Action) { a.BatchSize = 2 },
		"max failures unset": func(a *Action) { a.MaxFailures = nil },
		"max failures 0":     func(a *Action) { a.MaxFailures = &zero },
		"max failures 2":     func(a *Action) { a.MaxFailures = &two },
		"max targets unset":  func(a *Action) { a.MaxTargets = nil },
		"max targets 2":      func(a *Action) { a.MaxTargets = &two },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := jvmArthasAction("dashboard")
			mutate(&a)
			if _, err := ValidateAction(a); err == nil {
				t.Error("accepted")
			}
		})
	}
	a := jvmArthasAction("dashboard")
	a.MaxFailures = &one
	if _, err := ValidateAction(a); err != nil {
		t.Errorf("the fixed values: %v", err)
	}
}

const classPattern = `^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*$`

var (
	l2One     = int64(1)
	l2Class   = params.Definition{Type: params.String, Regex: classPattern, MaxLen: 255}
	l2Method  = params.Definition{Type: params.String, Regex: `^[A-Za-z_$][A-Za-z0-9_$]*$`, MaxLen: 255}
	l2Count   = params.Definition{Type: params.Int, Min: &l2One, Max: int64(5), Default: int64(1)}
	l2MinCost = params.Definition{Type: params.Int, Min: &l2One, Max: int64(3600000), Optional: true}
)

func TestJVMArthasParametersPerCommand(t *testing.T) {
	one := int64(1)
	target := params.Definition{Type: params.Enum, Description: "JVM target from the action's allowlist", Values: []string{"api", "web"}}
	cases := map[arthas.Kind]map[string]params.Definition{
		arthas.KindDashboard:       {},
		arthas.KindThreadBlocking:  {},
		arthas.KindMemory:          {},
		arthas.KindJVM:             {},
		arthas.KindClassLoaderTree: {},
		arthas.KindClassLoaderList: {},
		arthas.KindVersion:         {},
		arthas.KindThreadTop:       {"top": {Type: params.Int, Min: &one, Max: int64(10)}},
		arthas.KindThreadInfo:      {"thread_id": {Type: params.Int, Min: &one}},
		arthas.KindClassInfo:       {"class": {Type: params.String, Regex: classPattern, MaxLen: 255}},
		arthas.KindMethodInfo:      {"class": {Type: params.String, Regex: classPattern, MaxLen: 255}, "method": {Type: params.String, Regex: `^[A-Za-z_$][A-Za-z0-9_$]*$`, MaxLen: 255, Optional: true}},
		arthas.KindSysprop:         {"key": {Type: params.Enum, Values: []string{"java.version", "user.timezone"}}},
		arthas.KindWatch: {"class": l2Class, "method": l2Method, "count": l2Count, "min_cost_ms": l2MinCost,
			"express": {Type: params.Enum, Values: arthas.WatchExpressions(), Default: "params,returnObj"},
			"expand":  {Type: params.Int, Min: &one, Max: int64(2), Default: int64(1)}},
		arthas.KindTrace:   {"class": l2Class, "method": l2Method, "count": l2Count, "min_cost_ms": l2MinCost},
		arthas.KindStack:   {"class": l2Class, "method": l2Method, "count": l2Count, "min_cost_ms": l2MinCost},
		arthas.KindMonitor: {"class": l2Class, "method": l2Method, "count": l2Count, "min_cost_ms": l2MinCost, "cycle": {Type: params.Int, Min: &one, Max: int64(29)}},
		arthas.KindJad:     {"class": l2Class, "method": {Type: params.String, Regex: `^[A-Za-z_$][A-Za-z0-9_$]*$`, MaxLen: 255, Optional: true}},
	}
	for _, kind := range arthas.Kinds() {
		want, ok := cases[kind]
		if !ok {
			t.Fatalf("no expectation for %s", kind)
		}
		defs, err := ParameterDefinitions(jvmArthasAction(string(kind)))
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if got := defs["target"]; got.Type != target.Type || !slices.Equal(got.Values, target.Values) {
			t.Errorf("%s: target = %+v", kind, got)
		}
		delete(defs, "target")
		for name, w := range want {
			g, ok := defs[name]
			if !ok {
				t.Errorf("%s: no parameter %s", kind, name)
				continue
			}
			w.Description = g.Description // wording is free
			if g.Description == "" {
				t.Errorf("%s: parameter %s has no description", kind, name)
			}
			if !reflect.DeepEqual(g, w) {
				t.Errorf("%s: %s = %+v, want %+v", kind, name, g, w)
			}
			delete(defs, name)
		}
		if len(defs) != 0 {
			t.Errorf("%s: unexpected parameters %v", kind, defs)
		}
	}
}

// Every value the parameter layer lets through is accepted by arthas.Build, and the values it rejects
// include everything that could change the meaning of a command line.
func TestJVMArthasParameterValuesCannotCarryAnotherCommand(t *testing.T) {
	defs, err := ParameterDefinitions(jvmArthasAction("method_info"))
	if err != nil {
		t.Fatal(err)
	}
	for _, class := range []string{"java.lang.String", "com.example.Outer$Inner", "a.b.C_d1"} {
		values, err := params.Parse(defs, map[string]any{"target": "api", "class": class})
		if err != nil {
			t.Errorf("class %q: %v", class, err)
			continue
		}
		if _, err := arthas.Build(arthas.Request{Kind: arthas.KindMethodInfo, Class: values["class"].(string)}, arthas.Policy{}); err != nil {
			t.Errorf("class %q passed the parameters but not Build: %v", class, err)
		}
	}
	bad := []string{
		"", " ", "java.lang.String ognl", "java.lang.String;ognl", "java.lang.*", "java/lang/String", "java.lang.String\n", "java.lang.String\nstop",
		"$(id)", "`id`", "a|b", "a&b", "a>b", "a<b", "a,b", "a b", "-E", "-c 1", "a.b.", ".a", "a..b", "1a", "a\x00b", "a\tb", "ａ.b",
		"java.lang.String --classLoader x", strings.Repeat("a", 256), "#{1}", "@java.lang.Runtime@getRuntime()", "a'b", `a"b`, "a\\b",
	}
	for _, class := range bad {
		if _, err := params.Parse(defs, map[string]any{"target": "api", "class": class}); err == nil {
			t.Errorf("class %q was accepted by the parameters", class)
		}
		if _, err := arthas.Build(arthas.Request{Kind: arthas.KindMethodInfo, Class: class}, arthas.Policy{}); err == nil {
			t.Errorf("class %q was accepted by Build", class)
		}
	}
	for _, method := range []string{"a b", "run;stop", "run()", "*", "-x", "run\nstop", "a.b", "1a", strings.Repeat("m", 256)} {
		if _, err := params.Parse(defs, map[string]any{"target": "api", "class": "a.B", "method": method}); err == nil {
			t.Errorf("method %q was accepted by the parameters", method)
		}
	}
}

func TestJVMArthasThreadParameters(t *testing.T) {
	top, err := ParameterDefinitions(jvmArthasAction("thread_top"))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int64{1, 10} {
		if _, err := params.Parse(top, map[string]any{"target": "api", "top": n}); err != nil {
			t.Errorf("top %d: %v", n, err)
		}
	}
	for _, n := range []any{int64(0), int64(11), int64(-1), "5; stop", 1.5, "all"} {
		if _, err := params.Parse(top, map[string]any{"target": "api", "top": n}); err == nil {
			t.Errorf("top %v was accepted", n)
		}
	}
	info, err := ParameterDefinitions(jvmArthasAction("thread_info"))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []any{int64(0), int64(-1), "1; stop", "1 2", 2.5} {
		if _, err := params.Parse(info, map[string]any{"target": "api", "thread_id": n}); err == nil {
			t.Errorf("thread id %v was accepted", n)
		}
	}
	if _, err := params.Parse(info, map[string]any{"target": "api", "thread_id": int64(12345)}); err != nil {
		t.Errorf("thread id 12345: %v", err)
	}
}

func TestJVMArthasSyspropAcceptsOnlyTheConfiguredKeys(t *testing.T) {
	defs, err := ParameterDefinitions(jvmArthasAction("sysprop"))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"java.version", "user.timezone"} {
		if _, err := params.Parse(defs, map[string]any{"target": "api", "key": key}); err != nil {
			t.Errorf("key %q: %v", key, err)
		}
	}
	for _, key := range []string{"", "user.home", "java.version user.dir", "java.version=1", "*", "java.vers", "JAVA.VERSION"} {
		if _, err := params.Parse(defs, map[string]any{"target": "api", "key": key}); err == nil {
			t.Errorf("key %q was accepted", key)
		}
	}
}

func TestJVMArthasParameterOverridesOnlyTighten(t *testing.T) {
	a := jvmArthasAction("class_info")
	a.Params = map[string]params.Definition{"class": {Type: params.String, MaxLen: 100}}
	defs, err := ParameterDefinitions(a)
	if err != nil {
		t.Fatal(err)
	}
	if defs["class"].MaxLen != 100 {
		t.Errorf("max_len = %d", defs["class"].MaxLen)
	}
	for name, override := range map[string]params.Definition{
		"longer":   {Type: params.String, MaxLen: 300},
		"optional": {Type: params.String, Optional: true},
		"default":  {Type: params.String, Default: "java.lang.String"},
		"retyped":  {Type: params.Path},
	} {
		a := jvmArthasAction("class_info")
		a.Params = map[string]params.Definition{"class": override}
		if _, err := ParameterDefinitions(a); err == nil {
			t.Errorf("%s: loosened override accepted", name)
		}
	}
	a = jvmArthasAction("dashboard")
	a.Params = map[string]params.Definition{"pid": {Type: params.Int, Description: "pid"}}
	if _, err := ValidateAction(a); err == nil {
		t.Error("an action-level pid parameter was accepted")
	}
}

func TestJVMArthasRunMapsConfigParametersAndResult(t *testing.T) {
	var gotCfg jvmarthas.Config
	var gotParams jvmarthas.Params
	var gotMask func(string) string
	old := jvmArthasRun
	t.Cleanup(func() { jvmArthasRun = old })
	jvmArthasRun = func(ctx context.Context, cfg jvmarthas.Config, p jvmarthas.Params, mask func(string) string) (jvmarthas.Result, error) {
		gotCfg, gotParams, gotMask = cfg, p, mask
		return jvmarthas.Result{Stdout: "out\n", Stderr: "err\n", ExitCode: 1}, nil
	}
	cases := map[arthas.Kind]struct {
		values map[string]any
		want   arthas.Request
	}{
		arthas.KindDashboard:  {map[string]any{"target": "api"}, arthas.Request{}},
		arthas.KindThreadTop:  {map[string]any{"target": "api", "top": int64(3)}, arthas.Request{Top: 3}},
		arthas.KindThreadInfo: {map[string]any{"target": "api", "thread_id": int64(77)}, arthas.Request{ThreadID: 77}},
		arthas.KindClassInfo:  {map[string]any{"target": "api", "class": "a.B"}, arthas.Request{Class: "a.B"}},
		arthas.KindMethodInfo: {map[string]any{"target": "api", "class": "a.B", "method": "run"}, arthas.Request{Class: "a.B", Method: "run"}},
		arthas.KindSysprop:    {map[string]any{"target": "api", "key": "java.version"}, arthas.Request{Key: "java.version"}},
		arthas.KindWatch: {map[string]any{"target": "api", "class": "demo.A", "method": "run", "express": "returnObj", "expand": int64(2), "count": int64(3), "min_cost_ms": int64(50)},
			arthas.Request{Class: "demo.A", Method: "run", Express: "returnObj", Expand: 2, Count: 3, MinCost: 50}},
		arthas.KindTrace:   {map[string]any{"target": "api", "class": "demo.A", "method": "run", "count": int64(1)}, arthas.Request{Class: "demo.A", Method: "run", Count: 1}},
		arthas.KindStack:   {map[string]any{"target": "api", "class": "demo.A", "method": "run", "count": int64(5)}, arthas.Request{Class: "demo.A", Method: "run", Count: 5}},
		arthas.KindMonitor: {map[string]any{"target": "api", "class": "demo.A", "method": "run", "count": int64(2), "cycle": int64(10)}, arthas.Request{Class: "demo.A", Method: "run", Count: 2, Cycle: 10}},
		arthas.KindJad:     {map[string]any{"target": "api", "class": "demo.A"}, arthas.Request{Class: "demo.A"}},
	}
	for kind, tc := range cases {
		a := jvmArthasAction(string(kind))
		mask := func(s string) string { return "[" + s + "]" }
		res, err := jvmArthasHandler{}.RunRedacted(context.Background(), a.BuiltinConfig, tc.values, mask)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if res.Stdout != "out\n" || res.Stderr != "err\n" || res.ExitCode != 1 {
			t.Errorf("%s: result = %+v", kind, res)
		}
		want := tc.want
		want.Kind = kind
		if gotParams.Target != "api" || gotParams.Request != want {
			t.Errorf("%s: params = %+v, want request %+v", kind, gotParams, want)
		}
		if gotCfg.Command != kind || gotMask == nil || gotMask("x") != "[x]" {
			t.Errorf("%s: config command = %q, mask set = %v", kind, gotCfg.Command, gotMask != nil)
		}
	}
	// Run is the unmasked entry point.
	a := jvmArthasAction("dashboard")
	if _, err := (jvmArthasHandler{}).Run(context.Background(), a.BuiltinConfig, map[string]any{"target": "api"}); err != nil {
		t.Fatal(err)
	}
	if gotMask != nil {
		t.Error("Run passed a mask")
	}
}

func TestJVMArthasRunReportsErrors(t *testing.T) {
	old := jvmArthasRun
	t.Cleanup(func() { jvmArthasRun = old })
	boom := errors.New("context canceled")
	jvmArthasRun = func(context.Context, jvmarthas.Config, jvmarthas.Params, func(string) string) (jvmarthas.Result, error) {
		return jvmarthas.Result{Stdout: "partial", ExitCode: 1}, boom
	}
	a := jvmArthasAction("dashboard")
	res, err := jvmArthasHandler{}.RunRedacted(context.Background(), a.BuiltinConfig, map[string]any{"target": "api"}, nil)
	if !errors.Is(err, boom) || res.Stdout != "partial" || res.ExitCode != 1 {
		t.Errorf("result = %+v, err = %v", res, err)
	}
	if _, err := (jvmArthasHandler{}).RunRedacted(context.Background(), a.BuiltinConfig, map[string]any{}, nil); err == nil {
		t.Error("a call without target was accepted")
	}
	bad := maps.Clone(a.BuiltinConfig)
	bad["command"] = "ognl"
	if res, err := (jvmArthasHandler{}).RunRedacted(context.Background(), bad, map[string]any{"target": "api"}, nil); err == nil || res.ExitCode != 1 {
		t.Errorf("a bad config ran: %+v, %v", res, err)
	}
}

func TestJVMArthasRunsInTheRootHelperAndNeedsTheFiles(t *testing.T) {
	a := jvmArthasAction("dashboard")
	if !a.RequiresExec() {
		t.Error("jvm_arthas does not require allowops-exec")
	}
	old := jvmArthasInstalled
	t.Cleanup(func() { jvmArthasInstalled = old })
	jvmArthasInstalled = func() error { return nil }
	if support := CheckHost(a); !support.Supported || !support.RequiresExec || support.Status != "supported" {
		t.Errorf("installed: %+v", support)
	}
	jvmArthasInstalled = func() error { return errors.New("arthas-core.jar is missing") }
	support := CheckHost(a)
	if support.Supported || support.Status != "unsupported" || !strings.Contains(support.Reason, "arthas-core.jar") {
		t.Errorf("not installed: %+v", support)
	}
	// Other builtins are not affected.
	if support := CheckHost(jvmPerfdataAction()); !support.Supported {
		t.Errorf("jvm_perfdata: %+v", support)
	}
}

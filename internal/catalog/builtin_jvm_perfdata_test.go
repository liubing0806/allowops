package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/params"
)

func jvmPerfdataAction() Action {
	return Action{Name: "jvm_perfdata", Description: "JVM memory, GC and thread figures", Risk: "read", Builtin: "jvm_perfdata", BuiltinConfig: map[string]any{
		"targets": map[string]any{
			"web": map[string]any{"container": "shop-web", "main_class": "com.example.shop.Main"},
			"api": map[string]any{"systemd_unit": "api.service"},
		},
	}, Timeout: "5s", MaxOutput: 8192}
}

func TestJVMPerfdataIsRegistered(t *testing.T) {
	if _, ok := Builtins["jvm_perfdata"]; !ok {
		t.Fatal("jvm_perfdata is not registered")
	}
	if _, err := ValidateAction(jvmPerfdataAction()); err != nil {
		t.Fatal(err)
	}
}

func TestJVMPerfdataConfigRejectsWiderOrMalformedConfig(t *testing.T) {
	good := jvmPerfdataAction().BuiltinConfig
	tooMany := map[string]any{}
	for i := 0; i <= 64; i++ {
		tooMany[fmt.Sprintf("t%d", i)] = map[string]any{"systemd_unit": fmt.Sprintf("t%d.service", i)}
	}
	cases := map[string]func(map[string]any){
		"unknown field":     func(c map[string]any) { c["pid"] = 1 },
		"missing targets":   func(c map[string]any) { delete(c, "targets") },
		"empty targets":     func(c map[string]any) { c["targets"] = map[string]any{} },
		"targets not a map": func(c map[string]any) { c["targets"] = []any{"api.service"} },
		"too many targets":  func(c map[string]any) { c["targets"] = tooMany },
		"pid in a target": func(c map[string]any) {
			c["targets"] = map[string]any{"api": map[string]any{"systemd_unit": "api.service", "pid": 1}}
		},
		"path in a target": func(c map[string]any) {
			c["targets"] = map[string]any{"api": map[string]any{"systemd_unit": "api.service", "path": "/tmp"}}
		},
		"name in a target": func(c map[string]any) {
			c["targets"] = map[string]any{"api": map[string]any{"systemd_unit": "api.service", "name": "x"}}
		},
		"unit and container": func(c map[string]any) {
			c["targets"] = map[string]any{"api": map[string]any{"systemd_unit": "api.service", "container": "c", "main_class": "M"}}
		},
		"container without main": func(c map[string]any) { c["targets"] = map[string]any{"api": map[string]any{"container": "c"}} },
		"unit as an option": func(c map[string]any) {
			c["targets"] = map[string]any{"api": map[string]any{"systemd_unit": "--user.service"}}
		},
		"unit is not a service": func(c map[string]any) {
			c["targets"] = map[string]any{"api": map[string]any{"systemd_unit": "api.socket"}}
		},
		"bad target name": func(c map[string]any) {
			c["targets"] = map[string]any{"../api": map[string]any{"systemd_unit": "api.service"}}
		},
		"widened timeout":        func(c map[string]any) { c["timeout"] = "11s" },
		"negative timeout":       func(c map[string]any) { c["timeout"] = "-1s" },
		"timeout not a duration": func(c map[string]any) { c["timeout"] = "soon" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := jvmPerfdataAction()
			a.BuiltinConfig = maps.Clone(good)
			mutate(a.BuiltinConfig)
			if _, err := ValidateAction(a); err == nil {
				t.Errorf("accepted %v", a.BuiltinConfig)
			}
		})
	}
	a := jvmPerfdataAction()
	a.BuiltinConfig = maps.Clone(good)
	a.BuiltinConfig["timeout"] = "20ms"
	if _, err := ValidateAction(a); err != nil {
		t.Errorf("narrow timeout: %v", err)
	}
	a = jvmPerfdataAction()
	a.Params = map[string]params.Definition{"pid": {Type: params.Int, Description: "pid"}}
	if _, err := ValidateAction(a); err == nil {
		t.Error("an action-level pid parameter was accepted")
	}
}

// The caller can choose a target name from the allowlist and nothing else.
func TestJVMPerfdataParametersAreTheAllowlist(t *testing.T) {
	a := jvmPerfdataAction()
	defs, err := ParameterDefinitions(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(defs) != 1 || defs["target"].Type != params.Enum || !reflect.DeepEqual(defs["target"].Values, []string{"api", "web"}) {
		t.Fatalf("definitions = %+v", defs)
	}
	if values, err := params.Parse(defs, map[string]any{"target": "web"}); err != nil || values["target"] != "web" {
		t.Errorf("allowed target: %v, %v", values, err)
	}
	for _, input := range []map[string]any{
		{},
		{"target": "db"},
		{"target": "api.service"},
		{"target": "../../proc/1"},
		{"target": "api", "pid": 1},
		{"target": "api", "path": "/proc/1/root/etc"},
		{"pid": 1},
		{"path": "/tmp/hsperfdata_root/1"},
	} {
		if _, err := params.Parse(defs, input); err == nil {
			t.Errorf("accepted %v", input)
		}
	}
	schema, err := params.JSONSchema(defs)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(schema)
	if !strings.Contains(string(data), `"enum":["api","web"]`) {
		t.Errorf("schema = %s", data)
	}
}

func TestJVMPerfdataRunsInTheRootHelper(t *testing.T) {
	for _, runAs := range []string{"", "root"} {
		a := jvmPerfdataAction()
		a.RunAs = runAs
		if !a.RequiresExec() {
			t.Errorf("run_as=%q does not require allowops-exec", runAs)
		}
		if support := CheckHost(a); !support.RequiresExec || !support.Supported {
			t.Errorf("run_as=%q: %+v", runAs, support)
		}
	}
}

// A unit that does not exist is an operator-visible failure, not an error of the handler.
func TestJVMPerfdataRunReportsFailuresOnStderr(t *testing.T) {
	a := jvmPerfdataAction()
	a.BuiltinConfig["targets"] = map[string]any{"api": map[string]any{"systemd_unit": "allowops-no-such-unit.service"}}
	r, err := Builtins["jvm_perfdata"].Run(context.Background(), a.BuiltinConfig, map[string]any{"target": "api"})
	if err != nil || r.ExitCode != 1 || r.Stdout != "" || !strings.Contains(r.Stderr, `target "api"`) {
		t.Errorf("result = %+v, %v", r, err)
	}
	// A name outside the allowlist never reaches systemctl or Docker.
	r, err = Builtins["jvm_perfdata"].Run(context.Background(), a.BuiltinConfig, map[string]any{"target": "db"})
	if err != nil || r.ExitCode != 1 || !strings.Contains(r.Stderr, "allowed: api") {
		t.Errorf("unknown target: %+v, %v", r, err)
	}
}

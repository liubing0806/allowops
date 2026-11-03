package catalog

import (
	"slices"
	"testing"

	"github.com/liubing0806/allowops/internal/arthas"
)

// Every command has one example action of its own, and the examples agree on the files they check.
func TestJvmArthasExamplesCoverEveryCommandOnce(t *testing.T) {
	c := loadExamples(t)
	seen := map[arthas.Kind]string{}
	var files map[string]any
	for name, a := range c.Actions {
		if a.Builtin != "jvm_arthas" {
			continue
		}
		kind := arthas.Kind(a.BuiltinConfig["command"].(string))
		if other, dup := seen[kind]; dup {
			t.Errorf("%s and %s both run %s", other, name, kind)
		}
		seen[kind] = name
		if want := "jvm_arthas_" + string(kind); name != want {
			t.Errorf("action %s runs %s, want the name %s", name, kind, want)
		}
		if a.Risk != "write" || a.RunAs != "root" || a.BatchSize != 1 || *a.MaxTargets != 1 || *a.MaxFailures != 1 || *a.Idempotent {
			t.Errorf("%s: risk=%s run_as=%s batch=%d", name, a.Risk, a.RunAs, a.BatchSize)
		}
		if a.Redact == nil || !slices.Contains(a.Redact.Builtin, "secrets") {
			t.Errorf("%s does not redact secrets", name)
		}
		sum, _ := a.BuiltinConfig["sha256"].(map[string]any)
		if files == nil {
			files = sum
		}
		if len(sum) != 5 {
			t.Errorf("%s lists %d checksums", name, len(sum))
		}
		for file, v := range files {
			if sum[file] != v {
				t.Errorf("%s: checksum of %s differs from the other examples", name, file)
			}
		}
		defs, err := ParameterDefinitions(a)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if _, ok := defs["target"]; !ok {
			t.Errorf("%s has no target parameter", name)
		}
	}
	for _, kind := range arthas.Kinds() {
		if _, ok := seen[kind]; !ok {
			t.Errorf("no example action for %s", kind)
		}
	}
	if len(seen) != len(arthas.Kinds()) {
		t.Errorf("%d example actions for %d commands", len(seen), len(arthas.Kinds()))
	}
}

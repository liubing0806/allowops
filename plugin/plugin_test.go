package plugin

import (
	"strings"
	"testing"
)

type testModule struct{ id ModuleID }

func (m testModule) Module() ModuleInfo {
	return ModuleInfo{ID: m.id, New: func() Module { return &testModule{id: m.id} }}
}

func TestRegisterAndLookup(t *testing.T) {
	id := ModuleID("inventory.registry_test")
	Register(testModule{id})
	info, ok := Lookup(id)
	if !ok || info.ID != id || info.New().Module().ID != id {
		t.Fatalf("lookup: %+v, %v", info, ok)
	}
	if _, ok := Lookup("inventory.missing"); ok {
		t.Fatal("missing module found")
	}
	assertPanic(t, func() { Register(testModule{id}) })
}

func TestModuleID(t *testing.T) {
	for _, id := range []string{"", "inventory", "a.b.c", "Inventory.static", "inventory.host-labels", "1a.b", "a." + strings.Repeat("b", 33), strings.Repeat("a", 33) + ".b"} {
		t.Run(id, func(t *testing.T) { assertPanic(t, func() { Register(testModule{ModuleID(id)}) }) })
	}
	Register(testModule{ModuleID(strings.Repeat("a", 32) + "." + strings.Repeat("b", 32))})
}

func assertPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Error("expected panic")
		}
	}()
	f()
}

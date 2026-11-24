package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/pluginhost"
	"github.com/liubing0806/allowops/plugin/inventory"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func recommendNames(out inventoryResult, kind string) []string {
	names := []string{}
	for _, a := range out.RecommendedActions[kind] {
		names = append(names, a.Name)
	}
	return names
}

func entitySource(entities ...inventory.Entity) *inventoryStub {
	source := &inventoryStub{sources: []string{"static"}}
	for _, e := range entities {
		source.entities = append(source.entities, pluginhost.Result{Entity: e, Source: "static"})
	}
	return source
}

func TestEntitiesSearchRecommendedActions(t *testing.T) {
	source := entitySource(
		inventory.Entity{Kind: "service", Name: "api", Selector: "app=api"},
		inventory.Entity{Kind: "database", Name: "orders", Selector: "db=orders"},
		inventory.Entity{Kind: "cache", Name: "sessions", Selector: "cache=sessions"},
		inventory.Entity{Kind: "service", Name: "web", Selector: "app=web"},
		inventory.Entity{Kind: "secret", Name: "hidden", Hosts: []string{"private"}},
	)
	visible := progressiveActions()
	s := &Service{identity: &inventoryIdentity{visible: map[string]bool{}}, config: Config{Inventory: source}}
	result, err := s.searchEntities(context.Background(), nil, visible)
	if err != nil {
		t.Fatal(err)
	}
	out := result.StructuredContent.(inventoryResult)
	if len(out.Entities) != 4 || out.Truncated || out.RecommendedActionsTruncated || len(out.RecommendedActions) != 2 {
		t.Fatalf("result=%+v", out)
	}
	if got := recommendNames(out, "service"); !reflect.DeepEqual(got, []string{"logs_read", "svc_restart"}) {
		t.Fatalf("service=%v", got)
	}
	if got := out.RecommendedActions["database"]; !reflect.DeepEqual(got, []recommendedAction{{Name: "data_purge", Description: "Purge expired data", Risk: "dangerous"}}) {
		t.Fatalf("database=%v", got)
	}
	data := string(mustJSON(t, out))
	if !strings.Contains(data, `"toolset":"logs"`) || strings.Contains(data, "recommended_actions_truncated") || strings.Contains(data, "secret") {
		t.Fatalf("json=%s", data)
	}
	// Only kinds of entities kept after the limit are recommended.
	result, err = s.searchEntities(context.Background(), json.RawMessage(`{"limit":1}`), visible)
	if err != nil {
		t.Fatal(err)
	}
	out = result.StructuredContent.(inventoryResult)
	if !out.Truncated || len(out.RecommendedActions) != 1 || out.RecommendedActions["service"] == nil {
		t.Fatalf("limited=%+v", out)
	}
	// Without matching actions both fields are omitted.
	for _, actions := range []map[string]catalog.Action{nil, {"plain": {Name: "plain", Risk: "read"}}} {
		result, err = s.searchEntities(context.Background(), nil, actions)
		if err != nil {
			t.Fatal(err)
		}
		if data := string(mustJSON(t, result)); strings.Contains(data, "recommended_actions") {
			t.Fatalf("json=%s", data)
		}
	}
}

func TestEntitiesSearchRecommendationLimits(t *testing.T) {
	source := entitySource(inventory.Entity{Kind: "jvm", Name: "app", Selector: "app=jvm"})
	visible := map[string]catalog.Action{}
	for i, risk := range []string{"dangerous", "write", "read", "read", "write", "read", "read", "dangerous", "read", "read", "read", "read"} {
		name := fmt.Sprintf("jvm_%02d", i)
		visible[name] = catalog.Action{Name: name, Description: "JVM", Risk: risk, EntityKinds: []string{"jvm"}}
	}
	s := &Service{identity: &inventoryIdentity{}, config: Config{Inventory: source}}
	result, err := s.searchEntities(context.Background(), nil, visible)
	if err != nil {
		t.Fatal(err)
	}
	out := result.StructuredContent.(inventoryResult)
	want := []string{"jvm_02", "jvm_03", "jvm_05", "jvm_06", "jvm_08", "jvm_09", "jvm_10", "jvm_11", "jvm_01", "jvm_04"}
	if got := recommendNames(out, "jvm"); !reflect.DeepEqual(got, want) || !out.RecommendedActionsTruncated || out.Truncated {
		t.Fatalf("names=%v recommended truncated=%v truncated=%v", got, out.RecommendedActionsTruncated, out.Truncated)
	}

	// Groups that do not fit the remaining budget are omitted whole, in
	// kind order, without changing the entities.
	var entities []inventory.Entity
	visible = map[string]catalog.Action{}
	for _, kind := range []string{"a_kind", "b_kind", "c_kind", "d_kind"} {
		entities = append(entities, inventory.Entity{Kind: kind, Name: kind, Selector: "kind=" + kind})
		for i := range 2 {
			name := fmt.Sprintf("%s_%d", kind, i)
			visible[name] = catalog.Action{Name: name, Description: strings.Repeat(`"`, 1500), Risk: "read", EntityKinds: []string{kind}}
		}
	}
	s.config.Inventory = entitySource(entities...)
	result, err = s.searchEntities(context.Background(), nil, visible)
	if err != nil {
		t.Fatal(err)
	}
	out = result.StructuredContent.(inventoryResult)
	if size := len(mustJSON(t, result)); size > resultByteLimit {
		t.Fatalf("result has %d bytes", size)
	}
	if len(out.Entities) != 4 || out.Truncated || !out.RecommendedActionsTruncated || len(out.RecommendedActions) == 0 || len(out.RecommendedActions) == 4 {
		t.Fatalf("entities=%d truncated=%v recommended=%d recommended truncated=%v", len(out.Entities), out.Truncated, len(out.RecommendedActions), out.RecommendedActionsTruncated)
	}
	for kind, group := range out.RecommendedActions {
		if len(group) != 2 || kind > "b_kind" {
			t.Fatalf("group %s=%d", kind, len(group))
		}
	}

	// Entities filling the budget keep their own truncation and leave no
	// room for recommendations.
	entities = nil
	for i := range 100 {
		entities = append(entities, inventory.Entity{Kind: "jvm", Name: fmt.Sprintf("%03d%s", i, strings.Repeat("n", 600)), Selector: "app=jvm"})
	}
	s.config.Inventory = entitySource(entities...)
	visible = map[string]catalog.Action{"jvm_00": {Name: "jvm_00", Description: strings.Repeat("d", 4000), Risk: "read", EntityKinds: []string{"jvm"}}}
	result, err = s.searchEntities(context.Background(), json.RawMessage(`{"limit":100}`), visible)
	if err != nil {
		t.Fatal(err)
	}
	out = result.StructuredContent.(inventoryResult)
	if size := len(mustJSON(t, result)); size > resultByteLimit || !out.Truncated || out.RecommendedActions != nil || len(out.Entities) == 0 {
		t.Fatalf("size=%d truncated=%v recommended=%v", size, out.Truncated, out.RecommendedActions)
	}
}

// The tool call passes the request scope, so toolset narrowing also narrows
// recommendations.
func TestEntitiesSearchRecommendationsUseRequestScope(t *testing.T) {
	source := entitySource(inventory.Entity{Kind: "service", Name: "api", Selector: "app=api"})
	s := &Service{identity: &inventoryIdentity{}, config: Config{Inventory: source}}
	actions := progressiveActions()
	scope := &serverScope{tools: map[string]bool{"entities_search": true}, visible: map[string]catalog.Action{"svc_restart": actions["svc_restart"]}}
	result, err := s.execute(context.Background(), &sdk.CallToolRequest{Params: &sdk.CallToolParamsRaw{Name: "entities_search", Arguments: json.RawMessage(`{}`)}}, scope, &callState{})
	if err != nil {
		t.Fatal(err)
	}
	if got := recommendNames(result.StructuredContent.(inventoryResult), "service"); !reflect.DeepEqual(got, []string{"svc_restart"}) {
		t.Fatalf("service=%v", got)
	}
}

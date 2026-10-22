package authz

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestProtocolEmptyActionConditions(t *testing.T) {
	rules := []Rule{{ID: "execute", Roles: []string{"admin"}, Operations: []Operation{ExecuteAction}, Effect: "allow"}}
	e, err := newEngine(context.Background(), rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.Evaluate(context.Background(), Input{Subject: Subject{Roles: []string{"admin"}}, Operation: ExecuteAction, Action: Action{Name: "restart", Risk: "dangerous"}, Host: Host{Labels: map[string]string{"env": "test"}}})
	if err != nil || got.Decision != "allow" {
		t.Fatalf("empty actions/risks: decision=%s error=%v; want allow", got.Decision, err)
	}
}

func TestProtocolExplicitTimezone(t *testing.T) {
	var rule Rule
	if err := json.Unmarshal([]byte(`{"id":"hours","roles":["admin"],"operations":["modify_policy"],"effect":"allow","hours":{"from":9,"to":10,"timezone":"America/New_York"}}`), &rule); err != nil {
		t.Fatal(err)
	}
	e, err := newEngine(context.Background(), []Rule{rule}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.Evaluate(context.Background(), Input{Subject: Subject{Roles: []string{"admin"}}, Operation: ModifyPolicy, Env: Environment{TimeNS: time.Date(2026, 1, 1, 14, 30, 0, 0, time.UTC).UnixNano()}})
	if err != nil || got.Decision != "allow" {
		t.Fatalf("09:30 America/New_York: decision=%s error=%v; want allow", got.Decision, err)
	}
}

func TestProtocolRejectsMachineLocalTimezone(t *testing.T) {
	rule := Rule{ID: "hours", Roles: []string{"admin"}, Operations: []Operation{ModifyPolicy}, Effect: "allow", Hours: &Hours{From: 9, To: 10, Timezone: "Local"}}
	if _, err := newEngine(context.Background(), []Rule{rule}, nil); err == nil {
		t.Fatal("machine-local timezone accepted; want an explicit IANA timezone")
	}
}

package api

import (
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"testing"
)

func TestPolicyDigestEncodingIsCanonical(t *testing.T) {
	rules := &v1.PolicyRules{Rules: []*v1.PolicyRule{{Name: "named", Roles: []string{"admin"}, Operations: []string{"modify_policy"}, Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW}}}
	got, err := encode(rules)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"rules":[{"effect":"POLICY_EFFECT_ALLOW","name":"named","operations":["modify_policy"],"roles":["admin"]}]}`
	if string(got) != want {
		t.Fatalf("candidate encoding=%s; want canonical %s", got, want)
	}
}

package api

import (
	"context"
	"fmt"
	"testing"

	"connectrpc.com/connect"
)

// Each authorization still reads the current policy version, but the rules are
// loaded and decoded only when that version differs from the loaded one.
func TestPolicyRulesLoadOnlyWhenVersionChanges(t *testing.T) {
	log := &queryLog{}
	f := poolFixture(t, poolOptions{queries: log})
	ctx := context.Background()
	for i := range 20 {
		addHost(t, f, fmt.Sprintf("host-%02d", i))
	}
	if err := listHostsOnce(f, f.viewerToken, "host-01"); err != nil {
		t.Fatal(err)
	}
	before := log.count("policy_versions", "rules")
	versionReads := log.count("policy_versions")
	for range 3 {
		if err := listHostsOnce(f, f.viewerToken, "host-01"); err != nil {
			t.Fatal(err)
		}
	}
	if loads := log.count("policy_versions", "rules") - before; loads != 0 {
		t.Fatalf("policy rules loaded %d times by 3 requests over 20 hosts with an unchanged policy; want 0", loads)
	}
	if log.count("policy_versions") == versionReads {
		t.Fatal("authorization stopped reading the current policy version")
	}

	// A revocation committed between two requests, without any notification,
	// applies to the second request.
	rules := defaultRules()
	rules.Rules = rules.Rules[:1] // admin only: the viewer role loses view_hosts
	b, err := encode(rules)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Pool.Exec(ctx, "INSERT INTO policy_versions(version,rules,created_by,reason) VALUES (2,$1,'fixture','revoke viewer')", b); err != nil {
		t.Fatal(err)
	}
	before = log.count("policy_versions", "rules")
	code(t, listHostsOnce(f, f.viewerToken, "host-01"), connect.CodePermissionDenied)
	if loads := log.count("policy_versions", "rules") - before; loads != 1 {
		t.Fatalf("policy rules loaded %d times for one policy change; want 1", loads)
	}
}

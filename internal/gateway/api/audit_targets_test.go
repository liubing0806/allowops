package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/gateway/audit"
)

func persistedTargets(t *testing.T, f *fixture, operation, decision string) []audit.Payload {
	t.Helper()
	rows, err := f.db.Pool.Query(context.Background(), `SELECT hash_input FROM audit_events WHERE operation=$1 AND reason='result' AND decision=$2 ORDER BY seq`, operation, decision)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	events := []audit.Payload{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var e audit.Payload
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}
func requireTarget(t *testing.T, events []audit.Payload, kind string, ids ...string) {
	t.Helper()
	if len(events) != len(ids) {
		t.Fatalf("result event count=%d; want %d", len(events), len(ids))
	}
	for i, event := range events {
		var resource map[string]string
		if err := json.Unmarshal([]byte(event.Resource), &resource); err != nil {
			t.Fatalf("result resource[%d] is not a single-target JSON object: %v", i, err)
		}
		if len(resource) != 2 || resource["type"] != kind || resource["id"] != ids[i] {
			t.Errorf("result resource[%d] type=%q id=%q keys=%d; want exact type=%q id=%q and2 keys", i, resource["type"], resource["id"], len(resource), kind, ids[i])
		}
	}
}
func TestManagementResultAuditUsesActualTargets(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.service.Audit = NewAuditor(audit.New(f.db.Pool, audit.Config{}))
	accounts := rpc.NewServiceAccountServiceClient(f.server.Client(), f.server.URL, connect.WithInterceptors(bearerTest(f.adminToken)))
	created, err := accounts.CreateServiceAccount(ctx, connect.NewRequest(&v1.CreateServiceAccountRequest{Name: "secret-name-must-not-be-audited", OwnerUserId: f.admin.UserId, Description: "secret-description-must-not-be-audited"}))
	if err != nil {
		t.Fatal(err)
	}
	account := created.Msg.Account
	requireTarget(t, persistedTargets(t, f, rpc.ServiceAccountServiceCreateServiceAccountProcedure, "allow"), "service_account", account.AccountId)
	updated, err := accounts.UpdateServiceAccount(ctx, connect.NewRequest(&v1.UpdateServiceAccountRequest{AccountId: account.AccountId, OwnerUserId: f.admin.UserId, ExpectedRevision: account.Revision, Roles: []string{"viewer"}}))
	if err != nil {
		t.Fatal(err)
	}
	requireTarget(t, persistedTargets(t, f, rpc.ServiceAccountServiceUpdateServiceAccountProcedure, "allow"), "service_account", updated.Msg.Account.AccountId)
	token, err := accounts.CreateServiceAccountToken(ctx, connect.NewRequest(&v1.CreateServiceAccountTokenRequest{AccountId: account.AccountId}))
	if err != nil {
		t.Fatal(err)
	}
	requireTarget(t, persistedTargets(t, f, rpc.ServiceAccountServiceCreateServiceAccountTokenProcedure, "allow"), "service_account_token", token.Msg.Token.TokenId)
	_, err = accounts.RevokeServiceAccountToken(ctx, connect.NewRequest(&v1.RevokeServiceAccountTokenRequest{AccountId: account.AccountId, TokenId: token.Msg.Token.TokenId}))
	if err != nil {
		t.Fatal(err)
	}
	requireTarget(t, persistedTargets(t, f, rpc.ServiceAccountServiceRevokeServiceAccountTokenProcedure, "allow"), "service_account_token", token.Msg.Token.TokenId)
	userIDs := []string{}
	for _, user := range []*v1.User{f.admin, f.viewer} {
		_, err = f.users().SetUserRoles(ctx, connect.NewRequest(&v1.SetUserRolesRequest{UserId: user.UserId, ExpectedRevision: user.Revision, ManualRoles: []string{"admin"}}))
		if err != nil {
			t.Fatal(err)
		}
		userIDs = append(userIDs, user.UserId)
		requireTarget(t, persistedTargets(t, f, rpc.UserServiceSetUserRolesProcedure, "allow"), "user", userIDs...)
	}
	id := addHost(t, f, "delete-me")
	hosts := hostClient(f, f.adminToken)
	_, err = hosts.DeleteHost(ctx, connect.NewRequest(&v1.DeleteHostRequest{HostId: id, ExpectedRevision: "999"}))
	code(t, err, connect.CodeAborted)
	failed := persistedTargets(t, f, rpc.HostServiceDeleteHostProcedure, "deny")
	requireTarget(t, failed, "host", id)
	if success := persistedTargets(t, f, rpc.HostServiceDeleteHostProcedure, "allow"); len(success) != 0 {
		t.Fatalf("failed deletion recorded success: %v", success)
	}
	_, err = hosts.DeleteHost(ctx, connect.NewRequest(&v1.DeleteHostRequest{HostId: id, ExpectedRevision: "1"}))
	if err != nil {
		t.Fatal(err)
	}
	deleted := persistedTargets(t, f, rpc.HostServiceDeleteHostProcedure, "allow")
	requireTarget(t, deleted, "host", id)
	if deleted[0].Hostname != "delete-me" {
		t.Errorf("delete hostname=%q; want delete-me", deleted[0].Hostname)
	}
	var leaked int
	if err = f.db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE position($1 in convert_from(hash_input,'UTF8'))>0 OR position('secret-description' in convert_from(hash_input,'UTF8'))>0 OR position('secret-name' in convert_from(hash_input,'UTF8'))>0`, token.Msg.Secret).Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked != 0 {
		t.Errorf("secret/body leaked into %d events", leaked)
	}
}

func TestBulkAndCSVResultAuditRetainsAll5000Targets(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.service.Audit = NewAuditor(audit.New(f.db.Pool, audit.Config{}))
	// Populate only local fixture rows; both mutations still use the real RPC path.
	if _, err := f.db.Pool.Exec(ctx, `INSERT INTO hosts(host_id,hostname,authorization_labels,certificate_serial,certificate_expires_at) SELECT 'id-'||lpad(n::text,40,'0'),'host-'||lpad(n::text,4,'0'),'{"env":"test"}','fixture',now()+interval '1 hour' FROM generate_series(1,5000) n`); err != nil {
		t.Fatal(err)
	}
	revisions := []*v1.HostRevision{}
	csv := strings.Builder{}
	csv.WriteString("hostname,set:owner\n")
	for i := 1; i <= 5000; i++ {
		revisions = append(revisions, &v1.HostRevision{HostId: fmt.Sprintf("id-%040d", i), Revision: "1"})
		fmt.Fprintf(&csv, "host-%04d,secret-label-value\n", i)
	}
	client := hostClient(f, f.adminToken)
	bulk, err := client.SetHostLabels(ctx, connect.NewRequest(&v1.SetHostLabelsRequest{Targets: &v1.HostTargets{Selection: &v1.HostTargets_Selector{Selector: "env=test"}}, ExpectedCount: 5000, ExpectedRevisions: revisions, Changes: &v1.LabelChanges{Set: map[string]string{"owner": "secret-label-value"}}}))
	if err != nil {
		t.Fatal(err)
	}
	if bulk.Msg.UpdatedCount != 5000 {
		t.Fatal(bulk.Msg)
	}
	preview, err := client.PreviewHostImport(ctx, connect.NewRequest(&v1.PreviewHostImportRequest{Csv: []byte(csv.String())}))
	if err != nil {
		t.Fatal(err)
	}
	imported, err := client.ExecuteHostImport(ctx, connect.NewRequest(&v1.ExecuteHostImportRequest{PreviewId: preview.Msg.Preview.PreviewId}))
	if err != nil {
		t.Fatal(err)
	}
	if imported.Msg.UpdatedCount != 5000 {
		t.Fatal(imported.Msg)
	}
	// Delete the expiring preview. Audit must remain self-contained afterwards.
	if _, err = f.db.Pool.Exec(ctx, `DELETE FROM host_import_previews`); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{rpc.HostServiceSetHostLabelsProcedure, rpc.HostServiceExecuteHostImportProcedure} {
		events := persistedTargets(t, f, operation, "allow")
		targetIDs := map[string]bool{}
		expectedIDs := map[string]bool{}
		for _, revision := range revisions {
			expectedIDs[revision.HostId] = true
		}
		batchID := ""
		parts := map[int]bool{}
		targetCount := 0
		for _, event := range events {
			var part struct {
				BatchID            string `json:"batch_id"`
				Part, Parts, Total int
				Targets            []struct{ Type, ID string }
			}
			if err := json.Unmarshal([]byte(event.Resource), &part); err != nil {
				t.Errorf("invalid durable resource description: %v", err)
				continue
			}
			if batchID == "" {
				batchID = part.BatchID
			}
			if part.BatchID == "" || part.BatchID != batchID || part.Parts != len(events) || part.Total != 5000 || part.Part < 1 || part.Part > part.Parts || parts[part.Part] {
				t.Errorf("incomplete or unrelated batch resource: %s", event.Resource)
			}
			parts[part.Part] = true
			targetCount += len(part.Targets)
			for _, target := range part.Targets {
				if target.Type != "host" {
					t.Errorf("unexpected target type=%q", target.Type)
				}
				if !expectedIDs[target.ID] || targetIDs[target.ID] {
					t.Errorf("unexpected or duplicate target ID in batch")
				}
				targetIDs[target.ID] = true
			}
		}
		if targetCount != 5000 {
			t.Errorf("durable batch target count=%d; want 5000", targetCount)
		}
		missing := 0
		for id := range expectedIDs {
			if !targetIDs[id] {
				missing++
			}
		}
		if missing != 0 {
			t.Errorf("%s missing durable target IDs=%d/5000", operation, missing)
		}
	}
	var oversize, leaked int
	if err = f.db.Pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE octet_length(hash_input)>65536),count(*) FILTER(WHERE position('secret-label-value' in convert_from(hash_input,'UTF8'))>0) FROM audit_events`).Scan(&oversize, &leaked); err != nil {
		t.Fatal(err)
	}
	if oversize != 0 || leaked != 0 {
		t.Fatalf("oversize events=%d leaked label contents=%d", oversize, leaked)
	}
	var tail uint64
	if err = f.db.Pool.QueryRow(ctx, `SELECT max(seq) FROM audit_events`).Scan(&tail); err != nil {
		t.Fatal(err)
	}
	verified, err := audit.New(f.db.Pool, audit.Config{}).Verify(ctx, audit.VerifyOptions{From: 1, To: tail})
	if err != nil || !verified.Valid {
		t.Fatalf("chain=%+v error=%v", verified, err)
	}
}

func TestManagementAuditTargetInventory(t *testing.T) {
	f, key := catalogFixture(t)
	ctx := context.Background()
	f.service.Audit = NewAuditor(audit.New(f.db.Pool, audit.Config{}))
	f.service.management.config.CAPin = "sha256:" + strings.Repeat("0", 64)
	join := joinClient(f, f.adminToken)
	created, err := join.CreateJoinToken(ctx, connect.NewRequest(&v1.CreateJoinTokenRequest{MaxUses: 1}))
	if err != nil {
		t.Fatal(err)
	}
	requireTarget(t, persistedTargets(t, f, rpc.JoinTokenServiceCreateJoinTokenProcedure, "allow"), "join_token", created.Msg.Token.TokenId)
	_, err = join.RevokeJoinToken(ctx, connect.NewRequest(&v1.RevokeJoinTokenRequest{TokenId: created.Msg.Token.TokenId}))
	if err != nil {
		t.Fatal(err)
	}
	requireTarget(t, persistedTargets(t, f, rpc.JoinTokenServiceRevokeJoinTokenProcedure, "allow"), "join_token", created.Msg.Token.TokenId)
	mappings, err := f.users().GetRoleMappings(ctx, connect.NewRequest(&v1.GetRoleMappingsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	savedMappings, err := f.users().SaveRoleMappings(ctx, connect.NewRequest(&v1.SaveRoleMappingsRequest{ExpectedRevision: mappings.Msg.Revision, Mappings: mappings.Msg.Mappings}))
	if err != nil {
		t.Fatal(err)
	}
	requireTarget(t, persistedTargets(t, f, rpc.UserServiceSaveRoleMappingsProcedure, "allow"), "role_mappings", savedMappings.Msg.Revision)
	session, _, err := f.service.issueSession(ctx, f.db.Pool, f.viewer.UserId, v1.LoginClient_LOGIN_CLIENT_CLI)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.auth(f.adminToken).RevokeCliSession(ctx, connect.NewRequest(&v1.RevokeCliSessionRequest{UserId: f.viewer.UserId, SessionId: session.SessionId}))
	if err != nil {
		t.Fatal(err)
	}
	requireTarget(t, persistedTargets(t, f, rpc.AuthServiceRevokeCliSessionProcedure, "allow"), "cli_session", session.SessionId)
	p := f.policy(f.adminToken)
	tested, err := p.TestPolicy(ctx, connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: 1, Candidate: &v1.TestPolicyRequest_Rules{Rules: defaultRules()}}))
	if err != nil {
		t.Fatal(err)
	}
	requireTarget(t, persistedTargets(t, f, rpc.PolicyServiceTestPolicyProcedure, "allow"), "policy_test", tested.Msg.Test.TestId)
	saved, err := p.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 1, Rules: defaultRules(), TestId: tested.Msg.Test.TestId}))
	if err != nil {
		t.Fatal(err)
	}
	requireTarget(t, persistedTargets(t, f, rpc.PolicyServiceSavePolicyProcedure, "allow"), "policy_version", strconv.FormatUint(saved.Msg.Policy.Version, 10))
	rollbackTest, err := p.TestPolicy(ctx, connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: saved.Msg.Policy.Version, Candidate: &v1.TestPolicyRequest_HistoricalVersion{HistoricalVersion: 1}}))
	if err != nil {
		t.Fatal(err)
	}
	rollback, err := p.RollbackPolicy(ctx, connect.NewRequest(&v1.RollbackPolicyRequest{BaseVersion: saved.Msg.Policy.Version, TargetVersion: 1, TestId: rollbackTest.Msg.Test.TestId}))
	if err != nil {
		t.Fatal(err)
	}
	requireTarget(t, persistedTargets(t, f, rpc.PolicyServiceRollbackPolicyProcedure, "allow"), "policy_version", strconv.FormatUint(rollback.Msg.Policy.Version, 10))
	client := catalogClient(f, f.adminToken)
	raw := signedTestCatalog(t, key, "audited-catalog", "audited_action", time.Now())
	id := uploadTestCatalog(t, client, raw)
	requireTarget(t, persistedTargets(t, f, rpc.CatalogServiceBeginCatalogUploadProcedure, "allow"), "catalog_upload", id)
	requireTarget(t, persistedTargets(t, f, rpc.CatalogServiceUploadCatalogChunkProcedure, "allow"), "catalog_upload", id)
	published, err := client.PublishCatalog(ctx, connect.NewRequest(&v1.PublishCatalogRequest{UploadId: id}))
	if err != nil {
		t.Fatal(err)
	}
	ref := published.Msg.Catalog.Catalog
	requireTarget(t, persistedTargets(t, f, rpc.CatalogServicePublishCatalogProcedure, "allow"), "catalog_version", ref.CatalogId+"@"+strconv.FormatUint(ref.Version, 10))
	var leaked int
	if err = f.db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE position($1 in convert_from(hash_input,'UTF8'))>0 OR position('audited_action' in convert_from(hash_input,'UTF8'))>0`, created.Msg.Secret).Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked != 0 {
		t.Fatalf("credential/catalog body leaked into %d events", leaked)
	}
}

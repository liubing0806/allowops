//go:build production_invariants

package testpg_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/gateway/output"
	"github.com/liubing0806/allowops/internal/testpg"
	"google.golang.org/protobuf/proto"
)

// Admission must persist a task with the same login the deployed gateway uses.
// The host stays disconnected: this exercises submission without an agent or output storage.
func TestRuntimeRoleCanSubmitJob(t *testing.T) {
	pair := testpg.StartPair(t)
	st := openStore(t, pair.RuntimeDSN)
	ctx := t.Context()
	hostID := registerHost(t, st)
	_, err := st.Pool.Exec(ctx, `UPDATE hosts SET authorization_labels='{"env":"test"}' WHERE host_id=$1`, hostID)
	requireOK(t, err)
	trusted := publishCatalog(t, st)

	ledger := audit.New(st.Pool, audit.Config{})
	const origin = "https://gateway.test"
	access, err := api.New(ctx, st, api.Config{Origin: origin}, api.NewAuditor(ledger))
	requireOK(t, err)
	t.Cleanup(access.Close)
	_, err = st.Pool.Exec(ctx, `INSERT INTO console_users(user_id,provider_id,provider_subject,kind,username)
		VALUES ('owner','fixture','owner','oidc','owner');
		INSERT INTO service_accounts(account_id,name,owner_user_id,roles)
		VALUES ('operator','operator','owner','{admin}')`)
	requireOK(t, err)
	token, record, err := authn.GenerateServiceToken(time.Now(), 1)
	requireOK(t, err)
	_, err = st.Pool.Exec(ctx, `INSERT INTO service_account_tokens(token_id,account_id,token_hash,expires_at)
		VALUES ('operator-token','operator',$1,$2)`, record.Hash[:], record.ExpiresAt)
	requireOK(t, err)

	router, err := hostconn.New(st, nil, hostconn.DefaultConfig(), hostconn.Hooks{})
	requireOK(t, err)
	requireOK(t, st.Queries.RegisterInstance(ctx, router.InstanceID))
	jobs, err := job.New(st, access, router, &output.S3{}, ledger, trusted, job.DefaultConfig())
	requireOK(t, err)
	t.Cleanup(jobs.Close)

	request := httptest.NewRequestWithContext(ctx, http.MethodPost, origin+"/mcp", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	var result *v1.RunJobResponse
	access.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		result, err = jobs.RunJob(req.Context(), &v1.RunJobRequest{
			Action: "probe", Reason: "host probe", WaitSeconds: proto.Uint32(0),
			Targets: &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"runtime-host"}}}},
		})
	})).ServeHTTP(httptest.NewRecorder(), request)
	if err != nil {
		t.Fatalf("RunJob as %s: %v", pair.RuntimeRole, err)
	}
	var count int
	id := result.GetJob().GetJobId()
	requireOK(t, st.Pool.QueryRow(ctx, "SELECT count(*) FROM tasks WHERE job_id=$1 AND host_id=$2", id, hostID).Scan(&count))
	if count != 1 {
		t.Fatalf("committed tasks for job %q and host %q: got %d, want 1", id, hostID, count)
	}
}

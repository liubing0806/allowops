package job_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/authn"
	"github.com/liubing0806/allowops/internal/gateway/catalogsvc"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/params"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/store/db"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type approvalFixture struct {
	*fixture
	tokens map[string]string
	events notificationSink
}

type notificationSink chan job.ApprovalNotification

func (s notificationSink) NotifyApproval(ctx context.Context, event job.ApprovalNotification) {
	select {
	case s <- event:
	case <-ctx.Done():
	}
}

func setupApprovals(t *testing.T, maxConns int32, cfg job.ApprovalConfig, configure ...func(*fixture)) *approvalFixture {
	t.Helper()
	f := &approvalFixture{tokens: map[string]string{}, events: make(notificationSink, 128)}
	cfg.ConsoleBaseURL = "https://approvals.test"
	f.fixture = setup(t, func(base *fixture) {
		auditPool, err := store.OpenPool(t.Context(), base.DSN, 6)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(auditPool.Close)
		base.ApprovalAudit = audit.New(auditPool, audit.Config{})
		if maxConns > 0 {
			pool, err := store.OpenPool(t.Context(), base.DSN, maxConns)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			base.DB = &store.Store{Pool: pool, Queries: db.New(pool)}
		}
		base.ExtraActions = []catalog.Action{{
			Name: "gated", Description: "approval fixture", Risk: "read",
			Exec: []any{"/usr/bin/printf", "approved %s", "{duration}"}, Timeout: "5s", MaxOutput: 1024,
			Filters: []string{"count"},
			Params: map[string]params.Definition{
				"duration": {Type: params.Duration, Description: "duration", Default: "60s", Max: "5m"},
			},
		}}
		base.BeforeStart = func(_ *hostconn.Service, jobs *job.Service) {
			if err := jobs.ConfigureApprovals(cfg); err != nil {
				t.Fatal(err)
			}
			jobs.ApprovalNotifier = f.events
		}
		for _, customize := range configure {
			customize(base)
		}
	})
	for _, user := range []struct {
		id, email string
		roles     []string
	}{
		{"alice", "alice@example.test", []string{"reviewer"}},
		{"alias", " ALICE@EXAMPLE.TEST ", []string{"reviewer"}},
		{"bob", "bob@example.test", []string{"reviewer", "security"}},
		{"issuer", "issuer@example.test", []string{"reviewer", "executor"}},
		{"human", "human@example.test", []string{"requester", "reviewer"}},
		{"human-link", "HUMAN@example.test", []string{"reviewer"}},
		{"viewer", "viewer@example.test", []string{"viewer"}},
		{"guest", "guest@example.test", []string{}},
	} {
		f.exec(t, `INSERT INTO console_users(user_id,provider_id,provider_subject,kind,username,email,manual_roles)
			VALUES($1,'fixture',$1,'oidc',$1,$2,$3)`, user.id, user.email, user.roles)
	}
	f.exec(t, "UPDATE console_users SET email='owner@example.test',manual_roles='{admin,reviewer}' WHERE user_id='owner'")
	for _, user := range []string{"owner", "alice", "alias", "bob", "issuer", "human", "human-link", "viewer", "guest"} {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		token := "aops_cli_" + base64.RawURLEncoding.EncodeToString(key)
		hash := sha256.Sum256([]byte(token))
		f.exec(t, `INSERT INTO identity_sessions(session_id,user_id,token_hash,client,expires_at)
			VALUES($1,$1,$2,'cli',clock_timestamp()+interval '1 hour')`, user, hash[:])
		f.tokens[user] = token
	}
	foreign, record, err := authn.GenerateServiceToken(time.Now(), 1)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, "INSERT INTO service_accounts(account_id,name,owner_user_id,roles) VALUES('foreign','foreign','owner','{admin}')")
	f.exec(t, "INSERT INTO service_account_tokens(token_id,account_id,token_hash,expires_at) VALUES('foreign','foreign',$1,$2)", record.Hash[:], record.ExpiresAt)
	f.tokens["sa"], f.tokens["foreign"] = f.Token, foreign
	t.Cleanup(func() { awaitFixtureOutputs(t, f.fixture) })
	return f
}

func (f *approvalFixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := f.DB.Pool.Exec(ctx, sql, args...); err != nil {
		t.Fatal(err)
	}
}

func (f *approvalFixture) approvals(g *gateway, user string) rpc.ApprovalServiceClient {
	return rpc.NewApprovalServiceClient(g.HTTP, "https://"+g.Address, connect.WithInterceptors(bearer(f.tokens[user])))
}

func (f *approvalFixture) jobs(g *gateway, user string) rpc.JobServiceClient {
	return rpc.NewJobServiceClient(g.HTTP, "https://"+g.Address, connect.WithInterceptors(bearer(f.tokens[user])))
}

func approvalRule(minimum uint32, allowOwner bool, roles ...string) *v1.PolicyRule {
	return &v1.PolicyRule{
		Name: "approval-required", Effect: v1.PolicyEffect_POLICY_EFFECT_REQUIRE_APPROVAL,
		Roles: []string{"admin", "requester"}, Operations: []string{"execute_action"}, Actions: []string{"gated"},
		Approval: &v1.PolicyApprovalConfig{MinApprovals: minimum, ApproverRoles: roles, AllowOwnerApprove: allowOwner},
	}
}

func (f *approvalFixture) policy(t *testing.T, extra ...*v1.PolicyRule) uint64 {
	t.Helper()
	rules := []*v1.PolicyRule{
		{Name: "execute", Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW, Roles: []string{"admin", "requester", "executor"}, Operations: []string{"execute_action"}, HostLabels: map[string]string{"allowed": "yes"}},
		{Name: "approve", Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW, Roles: []string{"reviewer"}, Operations: []string{"approve_jobs"}, Actions: []string{"gated"}, SourceCidrs: []string{"127.0.0.0/8"}},
		{Name: "view-approvals", Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW, Roles: []string{"viewer"}, Operations: []string{"view_approvals"}, Actions: []string{"gated"}},
		{Name: "view-jobs", Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW, Roles: []string{"*"}, Operations: []string{"view_jobs", "view_output"}},
		{Name: "manage-tokens", Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW, Roles: []string{"executor"}, Operations: []string{"manage_service_accounts"}},
	}
	raw, err := protojson.Marshal(&v1.PolicyRules{Rules: append(rules, extra...)})
	if err != nil {
		t.Fatal(err)
	}
	var version uint64
	if err := f.DB.Pool.QueryRow(t.Context(), `INSERT INTO policy_versions(version,rules,created_by)
		SELECT max(version)+1,$1,'fixture' FROM policy_versions RETURNING version`, raw).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func (f *approvalFixture) labelTargets(t *testing.T) {
	f.exec(t, `UPDATE hosts SET authorization_labels='{"env":"test","allowed":"yes"}'`)
}

func gatedRequest() *v1.RunJobRequest {
	r := request("gated")
	r.WaitSeconds = nil
	return r
}

func (f *approvalFixture) submit(t *testing.T, user string, r *v1.RunJobRequest) *v1.Job {
	t.Helper()
	response, err := f.jobs(f.A, user).RunJob(t.Context(), connect.NewRequest(r))
	if err != nil {
		t.Fatal(err)
	}
	j := response.Msg.Job
	if j.Status != v1.JobStatus_JOB_STATUS_PENDING_APPROVAL || j.Approval == nil {
		t.Fatalf("pending job=%v", j)
	}
	return j
}

func (f *approvalFixture) metadata(t *testing.T, user, id string) *v1.ApprovalRequest {
	t.Helper()
	response, err := f.approvals(f.B, user).GetApproval(t.Context(), connect.NewRequest(&v1.GetApprovalRequest{ApprovalId: id}))
	if err != nil {
		t.Fatal(err)
	}
	return response.Msg.Approval
}

func approveMessage(a *v1.ApprovalRequest) *v1.ApproveRequestRequest {
	return &v1.ApproveRequestRequest{ApprovalId: a.ApprovalId, ExpectedRequestDigest: a.RequestDigest, Reason: "reviewed execution plan"}
}

func (f *approvalFixture) vote(t *testing.T, user string, a *v1.ApprovalRequest) (*connect.Response[v1.ApproveRequestResponse], error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	return f.approvals(f.B, user).ApproveRequest(ctx, connect.NewRequest(approveMessage(a)))
}

func requireApprovalError(t *testing.T, err error, code connect.Code, reason string) {
	t.Helper()
	if connect.CodeOf(err) != code || errorReason(err) != reason {
		t.Fatalf("error=%v detail=%q, want %v/%s", err, errorReason(err), code, reason)
	}
}

func (f *approvalFixture) assertTerminal(t *testing.T, j *v1.Job, wantApproval v1.ApprovalStatus, wantJob v1.JobStatus, taskReason string) {
	t.Helper()
	a := f.metadata(t, "viewer", j.Approval.ApprovalId)
	if a.Status != wantApproval || a.CanApprove {
		t.Fatalf("approval=%v, want terminal %s", a, wantApproval)
	}
	var status, cancelled, total int
	if err := f.DB.Pool.QueryRow(t.Context(), `SELECT j.status,count(*) FILTER(WHERE t.status=8 AND t.output_state='unavailable' AND NOT t.dispatched),count(*)
		FROM jobs j JOIN tasks t USING(job_id) WHERE j.job_id=$1 GROUP BY j.status`, j.JobId).Scan(&status, &cancelled, &total); err != nil {
		t.Fatal(err)
	}
	if status != int(wantJob) || uint64(total) != j.TotalTasks || cancelled != total {
		t.Fatalf("job status=%d cancelled=%d total=%d, want %s and %d cancelled tasks", status, cancelled, total, wantJob, j.TotalTasks)
	}
	taskPage, err := f.jobs(f.A, "viewer").ListTasks(t.Context(), connect.NewRequest(&v1.ListTasksRequest{JobId: j.JobId}))
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range taskPage.Msg.Tasks {
		if task.Result.Reason != taskReason {
			t.Errorf("task reason=%s, want %s", task.Result.Reason, taskReason)
		}
	}
}

func TestApprovalLifecycleSingleConnectionAndAuditChain(t *testing.T) {
	f := setupApprovals(t, 1, job.DefaultApprovalConfig())
	f.labelTargets(t)
	f.policy(t, approvalRule(2, false, "reviewer"))
	r := gatedRequest()
	r.ClientRequestId = "same-plan"
	r.Filters = &v1.OutputFilters{Count: proto.Bool(false)}
	pending := f.submit(t, "sa", r)
	a := f.metadata(t, "alice", pending.Approval.ApprovalId)
	if !a.CanApprove || a.ContextTrust != v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED || a.RequesterOwnerId != "owner" ||
		a.ConsoleUrl != "https://approvals.test/approvals/"+a.ApprovalId || a.NotifyStatus != "skipped" ||
		string(a.ParamsJson) != `{"duration":"1m0s"}` || string(a.FiltersJson) != `{"count":false}` || len(a.Targets) != 3 {
		t.Fatalf("approval metadata=%v", a)
	}
	duplicate := proto.CloneOf(r)
	duplicate.Params = &v1.Parameters{Json: []byte(`{"duration":"1m"}`)}
	if retry := f.submit(t, "sa", duplicate); retry.JobId != pending.JobId {
		t.Fatalf("idempotent retry=%s want=%s", retry.JobId, pending.JobId)
	}
	duplicate.Filters = nil
	_, err := f.A.Client.RunJob(t.Context(), connect.NewRequest(duplicate))
	requireApprovalError(t, err, connect.CodeAlreadyExists, "CLIENT_REQUEST_ID_CONFLICT")
	_, err = f.approvals(f.B, "guest").GetApproval(t.Context(), connect.NewRequest(&v1.GetApprovalRequest{ApprovalId: a.ApprovalId}))
	requireApprovalError(t, err, connect.CodePermissionDenied, "APPROVAL_ACCESS_DENIED")
	_, err = f.approvals(f.B, "foreign").GetApproval(t.Context(), connect.NewRequest(&v1.GetApprovalRequest{ApprovalId: a.ApprovalId}))
	requireApprovalError(t, err, connect.CodePermissionDenied, "APPROVAL_ACCESS_DENIED")
	if own := f.metadata(t, "sa", a.ApprovalId); own.CanApprove || own.CannotApproveReason != "HUMAN_APPROVER_REQUIRED" {
		t.Fatalf("service account approval view=%v", own)
	}
	_, err = f.vote(t, "sa", a)
	requireApprovalError(t, err, connect.CodePermissionDenied, "HUMAN_APPROVER_REQUIRED")
	list, err := f.approvals(f.B, "alice").ListApprovals(t.Context(), connect.NewRequest(&v1.ListApprovalsRequest{OnlyActionable: true}))
	if err != nil || len(list.Msg.Approvals) != 1 || list.Msg.Approvals[0].ApprovalId != a.ApprovalId {
		t.Fatalf("actionable queue=%v err=%v", list, err)
	}
	jobPage, err := f.A.Client.ListJobs(t.Context(), connect.NewRequest(&v1.ListJobsRequest{Statuses: []v1.JobStatus{v1.JobStatus_JOB_STATUS_PENDING_APPROVAL}}))
	if err != nil || len(jobPage.Msg.Jobs) != 1 || jobPage.Msg.Jobs[0].Approval.GetApprovalId() != a.ApprovalId {
		t.Fatalf("pending job list=%v err=%v", jobPage, err)
	}
	read, err := f.A.Client.GetJob(t.Context(), connect.NewRequest(&v1.GetJobRequest{JobId: pending.JobId}))
	if err != nil || read.Msg.Job.Status != v1.JobStatus_JOB_STATUS_PENDING_APPROVAL {
		t.Fatalf("immediate pending get=%v err=%v", read, err)
	}
	_, err = f.A.Client.GetJobOutput(t.Context(), connect.NewRequest(&v1.GetJobOutputRequest{JobId: pending.JobId, Hostname: "a-host", Stream: v1.OutputStream_OUTPUT_STREAM_STDOUT}))
	requireApprovalError(t, err, connect.CodeFailedPrecondition, "JOB_PENDING_APPROVAL")
	_, err = f.A.Client.DiffJobs(t.Context(), connect.NewRequest(&v1.DiffJobsRequest{BaseJobId: pending.JobId, TargetJobId: pending.JobId}))
	requireApprovalError(t, err, connect.CodeFailedPrecondition, "DIFF_JOB_NOT_FINISHED")
	bad := approveMessage(a)
	bad.ExpectedRequestDigest = make([]byte, sha256.Size)
	_, err = f.approvals(f.B, "alice").ApproveRequest(t.Context(), connect.NewRequest(bad))
	requireApprovalError(t, err, connect.CodeFailedPrecondition, "APPROVAL_DIGEST_MISMATCH")
	first, err := f.vote(t, "alice", a)
	if err != nil || first.Msg.Approval.Status != v1.ApprovalStatus_APPROVAL_STATUS_PENDING || first.Msg.Approval.ApprovedCount != 1 ||
		first.Msg.Job.Approval.ApprovedCount != 1 || first.Msg.Approval.CanApprove {
		t.Fatalf("first vote=%v err=%v", first, err)
	}
	_, err = f.vote(t, "alias", a)
	requireApprovalError(t, err, connect.CodeAlreadyExists, "ALREADY_APPROVED_BY_ACTOR")

	// Drop the selector label from one frozen host without removing the
	// execution label. The approved job must still dispatch to every frozen host.
	f.exec(t, `UPDATE hosts SET authorization_labels='{"allowed":"yes"}' WHERE hostname='c-host'`)
	// Gateway B hasn't refreshed its cache since the first vote. This writes
	// a higher version which the terminal transaction must load on its sole connection.
	version := f.policy(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	waited := make(chan *connect.Response[v1.GetJobResponse], 1)
	waitErr := make(chan error, 1)
	go func() {
		response, err := f.A.Client.GetJob(ctx, connect.NewRequest(&v1.GetJobRequest{JobId: pending.JobId, WaitSeconds: proto.Uint32(6)}))
		waited <- response
		waitErr <- err
	}()
	final, err := f.vote(t, "bob", a)
	if err != nil || final.Msg.Approval.Status != v1.ApprovalStatus_APPROVAL_STATUS_APPROVED ||
		final.Msg.Job.Status != v1.JobStatus_JOB_STATUS_QUEUED || final.Msg.Approval.GetRecheckPolicyVersion() != version ||
		len(final.Msg.Approval.Decisions) != 2 {
		t.Fatalf("terminal vote=%v err=%v", final, err)
	}
	out := <-waited
	if err := <-waitErr; err != nil || out.Msg.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED || out.Msg.Job.TotalTasks != 3 {
		t.Fatalf("long poll after approval=%v err=%v", out, err)
	}
	var nonce string
	var dispatched int
	if err := f.DB.Pool.QueryRow(t.Context(), `SELECT a.consume_nonce,count(*) FILTER(WHERE t.dispatched)
		FROM approval_requests a JOIN tasks t USING(job_id) WHERE a.approval_id=$1 GROUP BY a.consume_nonce`, a.ApprovalId).Scan(&nonce, &dispatched); err != nil || nonce == "" || dispatched != 3 {
		t.Fatalf("nonce present=%t dispatched=%d err=%v", nonce != "", dispatched, err)
	}
	eventSeq := map[string]int64{}
	for range 2 {
		select {
		case event := <-f.events:
			eventSeq[event.Type] = event.Sequence
			if event.ApprovalID != a.ApprovalId || event.TargetCount != 3 || event.EventID == "" {
				t.Fatalf("notification=%+v", event)
			}
		case <-ctx.Done():
			t.Fatal("timed out waiting for notification")
		}
	}
	if eventSeq["approval.requested"] != 1 || eventSeq["approval.approved"] != 2 {
		t.Fatalf("notification sequences=%v", eventSeq)
	}
	var to uint64
	if err := f.DB.Pool.QueryRow(t.Context(), "SELECT max(seq) FROM audit_events").Scan(&to); err != nil {
		t.Fatal(err)
	}
	verification, err := f.ApprovalAudit.Verify(t.Context(), audit.VerifyOptions{From: 1, To: to})
	if err != nil || !verification.Valid || verification.CheckedCount != to {
		t.Fatalf("audit verification=%+v err=%v", verification, err)
	}
}

func TestApprovalSeparationAndRechecks(t *testing.T) {
	cfg := job.DefaultApprovalConfig()
	cfg.SweepInterval = 5 * time.Minute
	f := setupApprovals(t, 0, cfg)
	f.labelTargets(t)

	t.Run("human_self_and_linked_identity", func(t *testing.T) {
		f.policy(t, approvalRule(1, true, "reviewer"))
		j := f.submit(t, "human", gatedRequest())
		a := f.metadata(t, "human", j.Approval.ApprovalId)
		if a.CanApprove || a.CannotApproveReason != "SELF_APPROVAL_FORBIDDEN" {
			t.Fatalf("requester projection=%v", a)
		}
		for _, actor := range []string{"human", "human-link"} {
			_, err := f.vote(t, actor, a)
			requireApprovalError(t, err, connect.CodePermissionDenied, "SELF_APPROVAL_FORBIDDEN")
		}
		// The requester can withdraw after losing execute_action, even when
		// calling the original JobService endpoint.
		f.exec(t, "UPDATE console_users SET manual_roles='{}' WHERE user_id='human'")
		got, err := f.jobs(f.A, "human").CancelJob(t.Context(), connect.NewRequest(&v1.CancelJobRequest{JobId: j.JobId}))
		if err != nil || got.Msg.Job.Status != v1.JobStatus_JOB_STATUS_CANCELLED ||
			got.Msg.Job.Approval.Status != v1.ApprovalStatus_APPROVAL_STATUS_CANCELLED {
			t.Fatalf("requester cancellation=%v err=%v", got, err)
		}
		f.exec(t, "UPDATE console_users SET manual_roles='{requester,reviewer}' WHERE user_id='human'")
	})

	t.Run("owner_issuer_and_owner_swap", func(t *testing.T) {
		f.policy(t, approvalRule(1, false, "reviewer"))
		f.exec(t, "UPDATE service_account_tokens SET created_by_user_id='owner' WHERE token_id='token'")
		j := f.submit(t, "sa", gatedRequest())
		a := f.metadata(t, "alice", j.Approval.ApprovalId)
		_, err := f.vote(t, "owner", a)
		requireApprovalError(t, err, connect.CodePermissionDenied, "SELF_APPROVAL_FORBIDDEN")
		f.exec(t, "UPDATE service_accounts SET owner_user_id='bob' WHERE account_id='sa'")
		for _, actor := range []string{"owner", "bob"} {
			_, err = f.vote(t, actor, a)
			requireApprovalError(t, err, connect.CodePermissionDenied, "SELF_APPROVAL_FORBIDDEN")
		}
		f.exec(t, "UPDATE service_accounts SET owner_user_id='owner' WHERE account_id='sa'")
		if _, err := f.approvals(f.A, "sa").CancelApproval(t.Context(), connect.NewRequest(&v1.CancelApprovalRequest{ApprovalId: a.ApprovalId})); err != nil {
			t.Fatal(err)
		}

		f.policy(t, approvalRule(1, true, "reviewer"))
		created, err := rpc.NewServiceAccountServiceClient(f.B.HTTP, "https://"+f.B.Address, connect.WithInterceptors(bearer(f.tokens["issuer"]))).
			CreateServiceAccountToken(t.Context(), connect.NewRequest(&v1.CreateServiceAccountTokenRequest{AccountId: "sa", Description: "issuer fixture", ValidDays: proto.Uint32(1)}))
		if err != nil {
			t.Fatal(err)
		}
		f.tokens["issued"] = created.Msg.Secret
		thirdPartyJob := f.submit(t, "issued", gatedRequest())
		thirdParty := f.metadata(t, "alice", thirdPartyJob.Approval.ApprovalId)
		var issuer string
		if err := f.DB.Pool.QueryRow(t.Context(), "SELECT requester_token_issuer_id FROM approval_requests WHERE approval_id=$1", thirdParty.ApprovalId).Scan(&issuer); err != nil || issuer != "issuer" {
			t.Fatalf("recorded issuer=%s err=%v", issuer, err)
		}
		_, err = f.vote(t, "issuer", thirdParty)
		requireApprovalError(t, err, connect.CodePermissionDenied, "SELF_APPROVAL_FORBIDDEN")
		f.exec(t, "UPDATE service_accounts SET owner_user_id='issuer' WHERE account_id='sa'")
		_, err = f.vote(t, "issuer", thirdParty)
		requireApprovalError(t, err, connect.CodePermissionDenied, "SELF_APPROVAL_FORBIDDEN")
		f.exec(t, "UPDATE service_accounts SET owner_user_id='owner' WHERE account_id='sa'")
		if approved, err := f.vote(t, "owner", thirdParty); err != nil || approved.Msg.Approval.Status != v1.ApprovalStatus_APPROVAL_STATUS_APPROVED {
			t.Fatalf("explicit owner approval=%v err=%v", approved, err)
		}
		if done := get(t, f.A, thirdParty.JobId); done.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED {
			t.Fatalf("owner-approved job=%v", done.Job)
		}
	})

	t.Run("veto", func(t *testing.T) {
		f.policy(t, approvalRule(2, false, "reviewer"))
		j := f.submit(t, "sa", gatedRequest())
		a := f.metadata(t, "alice", j.Approval.ApprovalId)
		if _, err := f.vote(t, "alice", a); err != nil {
			t.Fatal(err)
		}
		reject := &v1.RejectRequestRequest{ApprovalId: a.ApprovalId, Reason: "change window closed"}
		_, err := f.approvals(f.B, "alice").RejectRequest(t.Context(), connect.NewRequest(reject))
		requireApprovalError(t, err, connect.CodeAlreadyExists, "ALREADY_APPROVED_BY_ACTOR")
		resp, err := f.approvals(f.B, "bob").RejectRequest(t.Context(), connect.NewRequest(reject))
		if err != nil || resp.Msg.Approval.Status != v1.ApprovalStatus_APPROVAL_STATUS_REJECTED ||
			resp.Msg.Approval.ApprovedCount != 1 || len(resp.Msg.Approval.Decisions) != 2 ||
			resp.Msg.Approval.Decisions[1].Vote != v1.ApprovalVote_APPROVAL_VOTE_REJECT {
			t.Fatalf("single veto=%v err=%v", resp, err)
		}
		f.assertTerminal(t, j, v1.ApprovalStatus_APPROVAL_STATUS_REJECTED, v1.JobStatus_JOB_STATUS_DENIED, "APPROVAL_REJECTED")
	})

	t.Run("active_job_limit_preserves_pending_approval", func(t *testing.T) {
		f.policy(t, approvalRule(1, false, "reviewer"))
		j := f.submit(t, "sa", gatedRequest())
		a := f.metadata(t, "alice", j.Approval.ApprovalId)
		f.exec(t, `INSERT INTO jobs(job_id,created_at,subject_id,origin_instance,action,action_definition,
			catalog_id,catalog_version,action_sha256,policy_version,reason,status,batch_size,max_failures)
			SELECT 'active-limit-'||n, clock_timestamp(), subject_id, origin_instance, action, action_definition,
				catalog_id,catalog_version,action_sha256,policy_version,reason,1,1,0
			FROM jobs CROSS JOIN generate_series(1,5) n WHERE job_id=$1`, j.JobId)
		t.Cleanup(func() { f.exec(t, "DELETE FROM jobs WHERE job_id LIKE 'active-limit-%'") })
		_, err := f.vote(t, "alice", a)
		requireApprovalError(t, err, connect.CodeResourceExhausted, "CONCURRENT_JOB_LIMIT")
		if pending := f.metadata(t, "alice", a.ApprovalId); pending.Status != v1.ApprovalStatus_APPROVAL_STATUS_PENDING ||
			len(pending.Decisions) != 0 || pending.ApprovedCount != 0 || !pending.CanApprove {
			t.Fatalf("quota must roll back the vote and preserve approval: %v", pending)
		}
		f.exec(t, "DELETE FROM jobs WHERE job_id='active-limit-1'")
		if _, err := f.vote(t, "alice", a); err != nil {
			t.Fatal(err)
		}
		if done := get(t, f.A, j.JobId); done.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED {
			t.Fatalf("job after active quota freed=%v", done.Job)
		}
	})

	for _, scenario := range []struct {
		name, code, requester string
		firstVote             bool
		mutate                func(*testing.T)
	}{
		{"emergency_deny", "RECHECK_POLICY_DENIED", "sa", false, func(t *testing.T) {
			f.policy(t, &v1.PolicyRule{Name: "emergency", Effect: v1.PolicyEffect_POLICY_EFFECT_DENY, Roles: []string{"*"}, Operations: []string{"execute_action"}, Actions: []string{"gated"}})
		}},
		{"host_unlabeled", "RECHECK_HOST_UNLABELED", "sa", false, func(t *testing.T) {
			f.exec(t, "UPDATE hosts SET authorization_labels='{}' WHERE hostname='a-host'")
			t.Cleanup(func() { f.labelTargets(t) })
		}},
		{"requester_role_revoked", "RECHECK_POLICY_DENIED", "human", false, func(t *testing.T) {
			f.exec(t, "UPDATE console_users SET manual_roles='{reviewer}' WHERE user_id='human'")
			t.Cleanup(func() {
				f.exec(t, "UPDATE console_users SET manual_roles='{requester,reviewer}' WHERE user_id='human'")
			})
		}},
		{"token_revoked", "RECHECK_CREDENTIAL_REVOKED", "sa", false, func(t *testing.T) {
			f.exec(t, "UPDATE service_account_tokens SET revoked_at=clock_timestamp() WHERE token_id='token'")
			t.Cleanup(func() { f.exec(t, "UPDATE service_account_tokens SET revoked_at=NULL WHERE token_id='token'") })
		}},
		{"session_revoked", "RECHECK_CREDENTIAL_REVOKED", "human", false, func(t *testing.T) {
			f.exec(t, "UPDATE identity_sessions SET revoked_at=clock_timestamp() WHERE session_id='human'")
			t.Cleanup(func() { f.exec(t, "UPDATE identity_sessions SET revoked_at=NULL WHERE session_id='human'") })
		}},
		{"quorum_tightened", "RECHECK_POLICY_TIGHTENED", "sa", false, func(t *testing.T) {
			f.policy(t, approvalRule(2, false, "reviewer"))
		}},
		{"roles_tightened", "RECHECK_POLICY_TIGHTENED", "sa", false, func(t *testing.T) {
			f.policy(t, approvalRule(1, false, "security"))
		}},
		{"early_voter_lost_approval_role", "RECHECK_POLICY_TIGHTENED", "sa", true, func(t *testing.T) {
			f.exec(t, "UPDATE console_users SET manual_roles='{}' WHERE user_id='alice'")
			t.Cleanup(func() { f.exec(t, "UPDATE console_users SET manual_roles='{reviewer}' WHERE user_id='alice'") })
		}},
		{"host_deleted", "RECHECK_HOST_DELETED", "sa", false, func(t *testing.T) {
			f.exec(t, "UPDATE hosts SET certificate_status='deleted' WHERE hostname='a-host'")
			t.Cleanup(func() { f.exec(t, "UPDATE hosts SET certificate_status='active' WHERE hostname='a-host'") })
		}},
		{"catalog_action_changed", "RECHECK_CATALOG_CHANGED", "sa", false, func(t *testing.T) {
			next := make(map[string]catalog.Action, len(f.Package.Actions))
			for name, action := range f.Package.Actions {
				next[name] = action
			}
			changed := next["gated"]
			changed.Exec = []any{"/usr/bin/printf", "changed %s", "{duration}"}
			next["gated"] = changed
			newBuild, err := catalog.Build(&catalog.Catalog{Config: catalog.Config{SchemaVersion: 1, CatalogID: f.Package.CatalogID}, Actions: next},
				catalog.BuildOptions{Now: f.Package.CreatedAt.Add(2 * time.Second), TTL: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			payload, err := catalog.CanonicalJSON(newBuild)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := catalog.Sign(payload, catalog.SigningKey{PrivateKey: f.Signer})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			publication := &catalogsvc.Service{Store: f.DB, Trusted: f.Trusted, MaxEnvelopeBytes: 64 << 20, MaxActionBytes: 256 << 10}
			if _, err := publication.Publish(t.Context(), raw); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			minimum, finalActor := uint32(1), "alice"
			if scenario.firstVote {
				minimum, finalActor = 2, "bob"
			}
			f.policy(t, approvalRule(minimum, false, "reviewer"))
			j := f.submit(t, scenario.requester, gatedRequest())
			a := f.metadata(t, "alice", j.Approval.ApprovalId)
			if scenario.firstVote {
				if _, err := f.vote(t, "alice", a); err != nil {
					t.Fatal(err)
				}
			}
			scenario.mutate(t)
			_, err := f.vote(t, finalActor, a)
			requireApprovalError(t, err, connect.CodeFailedPrecondition, scenario.code)
			f.assertTerminal(t, j, v1.ApprovalStatus_APPROVAL_STATUS_EXECUTION_DENIED, v1.JobStatus_JOB_STATUS_DENIED, "RECHECK_DENIED")
			status := f.metadata(t, "viewer", a.ApprovalId)
			if status.RecheckError != scenario.code || status.GetRecheckPolicyVersion() == 0 {
				t.Fatalf("recheck details=%v want %s", status, scenario.code)
			}
		})
	}
}

func TestApprovalEvidenceQuotasPaginationAndLazyExpiry(t *testing.T) {
	cfg := job.DefaultApprovalConfig()
	cfg.SweepInterval, cfg.MaxPendingPerSubject, cfg.MaxPendingGlobal = 5*time.Minute, 1, 2
	f := setupApprovals(t, 0, cfg)
	f.labelTargets(t)
	f.policy(t, approvalRule(1, false, "reviewer"))
	foreign, err := f.jobs(f.A, "foreign").RunJob(t.Context(), connect.NewRequest(request("stable")))
	if err != nil {
		t.Fatal(err)
	}
	known := run(t, f.A, request("stable"))
	r := gatedRequest()
	for _, id := range []string{foreign.Msg.Job.JobId, "job-20000101-0001"} {
		r.Evidence = &v1.JobEvidence{JobIds: []string{id}}
		_, err := f.A.Client.RunJob(t.Context(), connect.NewRequest(r))
		requireApprovalError(t, err, connect.CodeInvalidArgument, "INVALID_EVIDENCE_JOB")
	}
	var leaked int
	if err := f.DB.Pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE subject_id='sa' AND operation='run_job' AND action='' AND reason='result' AND decision='deny'
		AND job_id <> ''`).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("evidence authorization mutated RunJob audit state: leaked=%d err=%v", leaked, err)
	}
	r.Evidence = &v1.JobEvidence{JobIds: []string{known.Job.JobId}, Summary: "Authorization: Bearer confidential-token"}
	r.ClientRequestId = "quota-test"
	j := f.submit(t, "sa", r)
	if a := f.metadata(t, "alice", j.Approval.ApprovalId); a.Evidence == nil || strings.Contains(a.Evidence.Summary, "confidential-token") || len(a.Evidence.JobIds) != 1 {
		t.Fatalf("stored evidence=%v", a.Evidence)
	}
	if retry := f.submit(t, "sa", r); retry.JobId != j.JobId {
		t.Fatalf("retry did not bypass quotas: %s", retry.JobId)
	}
	_, err = f.A.Client.RunJob(t.Context(), connect.NewRequest(gatedRequest()))
	requireApprovalError(t, err, connect.CodeResourceExhausted, "PENDING_APPROVAL_LIMIT")
	second := f.submit(t, "foreign", gatedRequest())
	_, err = f.jobs(f.A, "human").RunJob(t.Context(), connect.NewRequest(gatedRequest()))
	requireApprovalError(t, err, connect.CodeResourceExhausted, "PENDING_APPROVAL_LIMIT")

	pageReq := &v1.ListApprovalsRequest{Page: &v1.PageRequest{PageSize: 1}, OnlyActionable: true}
	page, err := f.approvals(f.B, "alice").ListApprovals(t.Context(), connect.NewRequest(pageReq))
	if err != nil || len(page.Msg.Approvals) != 1 || page.Msg.Page.NextPageToken == "" || page.Msg.Approvals[0].ApprovalId != second.Approval.ApprovalId {
		t.Fatalf("first approval page=%v err=%v", page, err)
	}
	pageReq.Page.PageToken = page.Msg.Page.NextPageToken
	last, err := f.approvals(f.B, "alice").ListApprovals(t.Context(), connect.NewRequest(pageReq))
	if err != nil || len(last.Msg.Approvals) != 1 || last.Msg.Page.NextPageToken != "" || last.Msg.Approvals[0].ApprovalId != j.Approval.ApprovalId {
		t.Fatalf("last approval page=%v err=%v", last, err)
	}
	_, err = f.approvals(f.B, "bob").ListApprovals(t.Context(), connect.NewRequest(pageReq))
	requireApprovalError(t, err, connect.CodeInvalidArgument, "INVALID_PAGE_TOKEN")
	own, err := f.approvals(f.B, "sa").ListApprovals(t.Context(), connect.NewRequest(&v1.ListApprovalsRequest{}))
	if err != nil || len(own.Msg.Approvals) != 1 || own.Msg.Approvals[0].ApprovalId != j.Approval.ApprovalId {
		t.Fatalf("requester queue=%v err=%v", own, err)
	}
	_, err = f.approvals(f.B, "alice").CancelApproval(t.Context(), connect.NewRequest(&v1.CancelApprovalRequest{ApprovalId: second.Approval.ApprovalId}))
	requireApprovalError(t, err, connect.CodePermissionDenied, "JOB_OPERATION_DENIED")
	cancelled, err := f.approvals(f.B, "issuer").CancelApproval(t.Context(), connect.NewRequest(&v1.CancelApprovalRequest{ApprovalId: second.Approval.ApprovalId}))
	if err != nil || cancelled.Msg.Approval.Status != v1.ApprovalStatus_APPROVAL_STATUS_CANCELLED {
		t.Fatalf("cancel with execute permission=%v err=%v", cancelled, err)
	}

	a := f.metadata(t, "alice", j.Approval.ApprovalId)
	f.exec(t, `UPDATE approval_requests
		SET created_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 second'
		WHERE approval_id=$1`, a.ApprovalId)
	_, err = f.vote(t, "alice", a)
	requireApprovalError(t, err, connect.CodeFailedPrecondition, "APPROVAL_EXPIRED")
	f.assertTerminal(t, j, v1.ApprovalStatus_APPROVAL_STATUS_EXPIRED, v1.JobStatus_JOB_STATUS_DENIED, "APPROVAL_EXPIRED")
	_ = f.submit(t, "sa", gatedRequest())
}

func TestApprovalConcurrentVotesAndTerminalTransitions(t *testing.T) {
	cfg := job.DefaultApprovalConfig()
	cfg.SweepInterval = time.Second
	f := setupApprovals(t, 0, cfg)
	f.labelTargets(t)
	f.policy(t, approvalRule(1, false, "reviewer"))
	j := f.submit(t, "sa", gatedRequest())
	a := f.metadata(t, "alice", j.Approval.ApprovalId)
	var wg sync.WaitGroup
	results := make(chan error, 10)
	for i := range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g := f.A
			if i%2 == 1 {
				g = f.B
			}
			_, err := f.approvals(g, "alice").ApproveRequest(t.Context(), connect.NewRequest(approveMessage(a)))
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			requireApprovalError(t, err, connect.CodeFailedPrecondition, "APPROVAL_NOT_PENDING")
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent votes=%d, want 1", successes)
	}
	if done := get(t, f.A, j.JobId); done.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED {
		t.Fatalf("concurrent consumption job=%v", done.Job)
	}
	row := f.metadata(t, "viewer", a.ApprovalId)
	if len(row.Decisions) != 1 || row.ApprovedCount != 1 {
		t.Fatalf("concurrent vote rows=%v", row.Decisions)
	}

	// Every worker contests the same locked approval. The sweeper runs on
	// both gateways and may skip the row while another transition owns it.
	racing := f.submit(t, "sa", gatedRequest())
	a = f.metadata(t, "alice", racing.Approval.ApprovalId)
	f.exec(t, `UPDATE approval_requests
		SET expires_at=clock_timestamp()+interval '300 milliseconds' WHERE approval_id=$1`, a.ApprovalId)
	start := make(chan struct{})
	contenders := []func() error{
		func() error { _, err := f.vote(t, "alice", a); return err },
		func() error {
			_, err := f.approvals(f.A, "bob").RejectRequest(t.Context(), connect.NewRequest(&v1.RejectRequestRequest{ApprovalId: a.ApprovalId, Reason: "veto"}))
			return err
		},
		func() error {
			_, err := f.A.Client.CancelJob(t.Context(), connect.NewRequest(&v1.CancelJobRequest{JobId: racing.JobId}))
			return err
		},
	}
	errors := make(chan error, len(contenders))
	for _, contender := range contenders {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; errors <- contender() }()
	}
	close(start)
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil && connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Errorf("unexpected transition error %v", err)
		}
	}
	var status int
	var seq int64
	if err := f.DB.Pool.QueryRow(t.Context(), "SELECT status,notify_seq FROM approval_requests WHERE approval_id=$1", a.ApprovalId).Scan(&status, &seq); err != nil || status < 2 || status > 5 || seq != 2 {
		t.Fatalf("contested transition status=%d seq=%d err=%v", status, seq, err)
	}
	if status == int(v1.ApprovalStatus_APPROVAL_STATUS_APPROVED) {
		get(t, f.A, racing.JobId)
	}

	expiring := f.submit(t, "sa", gatedRequest())
	f.exec(t, `UPDATE approval_requests
		SET created_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 second'
		WHERE approval_id=$1`, expiring.Approval.ApprovalId)
	eventually(t, func() bool {
		return f.metadata(t, "viewer", expiring.Approval.ApprovalId).Status == v1.ApprovalStatus_APPROVAL_STATUS_EXPIRED
	})
	f.assertTerminal(t, expiring, v1.ApprovalStatus_APPROVAL_STATUS_EXPIRED, v1.JobStatus_JOB_STATUS_DENIED, "APPROVAL_EXPIRED")
	var audits int
	if err := f.DB.Pool.QueryRow(t.Context(), "SELECT count(*) FROM audit_events WHERE job_id=$1 AND operation='expire_approval'", expiring.JobId).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("expiry audit count=%d err=%v", audits, err)
	}
}

func TestApprovalConsumeNonceRecoversLostCommit(t *testing.T) {
	var proxy *commitLossProxy
	f := setupApprovals(t, 0, job.DefaultApprovalConfig(), func(f *fixture) {
		proxy = newCommitLossProxy(t, f.DB, "SET status=2, approved_count=")
		proxy.outage = 500 * time.Millisecond
		proxied := proxiedJobStore(t, f.DB, proxy)
		beforeStart := f.BeforeStart
		f.BeforeStart = func(hosts *hostconn.Service, jobs *job.Service) {
			beforeStart(hosts, jobs)
			if f.A != nil {
				jobs.Store = proxied
			}
		}
	})
	f.labelTargets(t)
	f.policy(t, approvalRule(1, false, "reviewer"))
	j := f.submit(t, "sa", gatedRequest())
	a := f.metadata(t, "alice", j.Approval.ApprovalId)
	approved, err := f.vote(t, "alice", a)
	if !proxy.fired.Load() || err != nil || approved.Msg.Approval.Status != v1.ApprovalStatus_APPROVAL_STATUS_APPROVED {
		t.Fatalf("lost consume commit fired=%t response=%v err=%v", proxy.fired.Load(), approved, err)
	}
	if done := get(t, f.A, j.JobId); done.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED {
		t.Fatalf("job after lost consume commit=%v", done.Job)
	}
	_, err = f.vote(t, "alice", a)
	requireApprovalError(t, err, connect.CodeFailedPrecondition, "APPROVAL_NOT_PENDING")
}

func TestApprovalRunJobExplicitWaitAndDenyPrecedence(t *testing.T) {
	f := setupApprovals(t, 0, job.DefaultApprovalConfig())
	f.labelTargets(t)
	approval := approvalRule(1, false, "reviewer")
	approval.HostLabels = map[string]string{"gated": "yes"}
	deny := &v1.PolicyRule{
		Name: "one-host-denies", Effect: v1.PolicyEffect_POLICY_EFFECT_DENY, Roles: []string{"*"},
		Operations: []string{"execute_action"}, Actions: []string{"gated"}, HostLabels: map[string]string{"deny": "yes"},
	}
	f.policy(t, approval, deny)
	f.exec(t, `UPDATE hosts SET authorization_labels=authorization_labels||'{"gated":"yes"}' WHERE hostname='a-host';
		UPDATE hosts SET authorization_labels=authorization_labels||'{"deny":"yes"}' WHERE hostname='b-host';`)
	_, err := f.A.Client.RunJob(t.Context(), connect.NewRequest(gatedRequest()))
	requireApprovalError(t, err, connect.CodePermissionDenied, "JOB_DENIED")
	var count int
	if err := f.DB.Pool.QueryRow(t.Context(), "SELECT count(*) FROM approval_requests").Scan(&count); err != nil || count != 0 {
		t.Fatalf("approval rows after host denial=%d err=%v", count, err)
	}
	f.exec(t, "UPDATE hosts SET authorization_labels=authorization_labels-'deny' WHERE hostname='b-host'")
	r := gatedRequest()
	r.WaitSeconds = proto.Uint32(8)
	type result struct {
		response *connect.Response[v1.RunJobResponse]
		err      error
	}
	done := make(chan result, 1)
	go func() {
		response, err := f.A.Client.RunJob(t.Context(), connect.NewRequest(r))
		done <- result{response, err}
	}()
	var id string
	eventually(t, func() bool {
		err := f.DB.Pool.QueryRow(t.Context(), "SELECT approval_id FROM approval_requests WHERE status=1").Scan(&id)
		return err == nil
	})
	select {
	case got := <-done:
		t.Fatalf("explicit RunJob wait returned early: %v err=%v", got.response, got.err)
	default:
	}
	a := f.metadata(t, "alice", id)
	if len(a.Targets) != 3 {
		t.Fatalf("mixed allow and approval targets=%v", a.Targets)
	}
	if _, err := f.vote(t, "alice", a); err != nil {
		t.Fatal(err)
	}
	if got := <-done; got.err != nil || got.response.Msg.Job.Status != v1.JobStatus_JOB_STATUS_SUCCEEDED ||
		got.response.Msg.Job.Approval.Status != v1.ApprovalStatus_APPROVAL_STATUS_APPROVED {
		t.Fatalf("RunJob wait through execution=%v err=%v", got.response, got.err)
	}
}

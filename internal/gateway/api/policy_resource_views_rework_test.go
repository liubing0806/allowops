package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/catalogsvc"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
	"google.golang.org/protobuf/proto"
)

type viewFixtureOutput []byte

func (v viewFixtureOutput) Put(context.Context, string, []byte) error {
	return fmt.Errorf("read-only output fixture")
}
func (v viewFixtureOutput) Get(context.Context, string, int64) ([]byte, error) {
	return bytes.Clone(v), nil
}

type viewPolicyFixture struct {
	identity *api.Service
	policy   rpc.PolicyServiceClient
	catalog  rpc.CatalogServiceClient
	jobs     rpc.JobServiceClient
	jobIDs   map[[2]string]string
	output   []byte
}

func newViewPolicyFixture(t *testing.T) *viewPolicyFixture {
	t.Helper()
	ctx := context.Background()
	dsn := testpg.Start(t)
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	server := httptest.NewUnstartedServer(nil)
	auditor := audit.New(db.Pool, audit.Config{})
	identity, err := api.New(ctx, db, api.Config{Origin: "https://" + server.Listener.Addr().String()}, api.NewAuditor(auditor))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(identity.Close)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	catalogs := &catalogsvc.Service{Store: db, Trusted: map[string]ed25519.PublicKey{catalog.KeyID(pub): pub}, MaxEnvelopeBytes: 1 << 20, MaxActionBytes: 256 << 10}
	if err = identity.ConfigureManagement(api.ManagementConfig{}, nil, catalogs); err != nil {
		t.Fatal(err)
	}
	actions := map[string]catalog.Action{}
	for name, risk := range map[string]string{"read_action": "read", "danger_action": "dangerous"} {
		actions[name] = catalog.Action{Name: name, Description: "view fixture", Risk: risk, Exec: []any{"/usr/bin/true"}, Timeout: "1s", MaxOutput: 1024}
	}
	pkg, err := catalog.Build(&catalog.Catalog{Config: catalog.Config{SchemaVersion: 1, CatalogID: "view-fixture"}, Actions: actions}, catalog.BuildOptions{Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := catalog.CanonicalJSON(pkg)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := catalog.Sign(raw, catalog.SigningKey{PrivateKey: key})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = catalogs.Publish(ctx, signed); err != nil {
		t.Fatal(err)
	}
	mint := func(id, role string) string {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, `INSERT INTO console_users(user_id,provider_id,provider_subject,kind,username,manual_roles) VALUES ($1,'fixture',$1,'ldap',$1,$2)`, id, []string{role}); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		token := "aops_cli_" + base64.RawURLEncoding.EncodeToString(b)
		sum := sha256.Sum256([]byte(token))
		if _, err := db.Pool.Exec(ctx, `INSERT INTO identity_sessions(session_id,user_id,token_hash,client,expires_at) VALUES ($1,$1,$2,'cli',now()+interval '1 hour')`, id, sum[:]); err != nil {
			t.Fatal(err)
		}
		return token
	}
	admin, inspector := mint("admin", "admin"), mint("inspector", "inspector")
	for _, name := range []string{"dev", "prod"} {
		if _, err := db.Pool.Exec(ctx, `INSERT INTO hosts(host_id,hostname,authorization_labels,certificate_serial,certificate_expires_at) VALUES ($1,$1,jsonb_build_object('env',$1::text),'fixture',now()+interval '1 hour')`, name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO gateway_instances(instance_id,last_seen) VALUES ('view-fixture',now()); CREATE TABLE tasks_view_fixture PARTITION OF tasks DEFAULT`); err != nil {
		t.Fatal(err)
	}
	data := []byte("fixture output\n")
	sum := sha256.Sum256(data)
	result, err := proto.Marshal(&v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_SUCCEEDED, ExitCode: proto.Int32(0), Stdout: &v1.OutputMetadata{SizeBytes: uint64(len(data)), Sha256: sum[:]}})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[[2]string]string{}
	at := time.Now().UTC().Truncate(time.Microsecond)
	for i, name := range []string{"danger_action", "read_action"} {
		definition, err := json.Marshal(actions[name])
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(definition)
		for j, host := range []string{"dev", "prod"} {
			id := fmt.Sprintf("job-%s-%04d", at.Format("20060102"), i*2+j+1)
			ids[[2]string{name, host}] = id
			if _, err := db.Pool.Exec(ctx, `INSERT INTO jobs(job_id,created_at,subject_id,origin_instance,action,action_definition,catalog_id,catalog_version,action_sha256,policy_version,reason,status,batch_size,max_failures,finished_at) VALUES ($1,$2,'admin','view-fixture',$3,$4,'view-fixture',$5,$6,1,'fixture',$7,1,0,$2)`, id, at, name, definition, pkg.Version, digest[:], int16(v1.JobStatus_JOB_STATUS_SUCCEEDED)); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Pool.Exec(ctx, `INSERT INTO tasks(job_id,task_id,created_at,host_id,hostname,position,status,result,finished_at,output_stored,output_state) VALUES ($1,$1,$2,$3,$3,0,3,$4,$2,true,'stored')`, id, at, host, result); err != nil {
				t.Fatal(err)
			}
		}
	}
	router, err := hostconn.New(db, nil, hostconn.DefaultConfig(), hostconn.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := job.New(db, identity, router, viewFixtureOutput(data), auditor, catalogs.Trusted, job.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(jobs.Close)
	mux := http.NewServeMux()
	mux.Handle("/allowops.v1.JobService/", jobs.Handler())
	mux.Handle("/", identity.Handler())
	server.Config.Handler = mux
	server.StartTLS()
	t.Cleanup(server.Close)
	bearer := func(token string) connect.Interceptor {
		return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
			return func(ctx context.Context, r connect.AnyRequest) (connect.AnyResponse, error) {
				r.Header().Set("Authorization", "Bearer "+token)
				return next(ctx, r)
			}
		})
	}
	return &viewPolicyFixture{identity: identity, policy: rpc.NewPolicyServiceClient(server.Client(), server.URL, connect.WithInterceptors(bearer(admin))), catalog: rpc.NewCatalogServiceClient(server.Client(), server.URL, connect.WithInterceptors(bearer(inspector))), jobs: rpc.NewJobServiceClient(server.Client(), server.URL, connect.WithInterceptors(bearer(inspector))), jobIDs: ids, output: data}
}

func TestDefaultPolicyTrialIncludesLiveJobAndCatalogViews(t *testing.T) {
	f := newViewPolicyFixture(t)
	ctx := context.Background()
	wait := uint32(0)
	// Real P6 read handlers initially deny both action risks on both hosts.
	// After the rule is saved, view_jobs, view_output and view_catalog apply its
	// actions/risks filter (RR-b-01): read_action is allowed, danger_action is not.
	assertViews := func(after bool) {
		t.Helper()
		for _, name := range []string{"danger_action", "read_action"} {
			for _, host := range []string{"dev", "prod"} {
				allow := after && name == "read_action"
				id := f.jobIDs[[2]string{name, host}]
				metadata, err := f.jobs.GetJob(ctx, connect.NewRequest(&v1.GetJobRequest{JobId: id, WaitSeconds: &wait}))
				if allow {
					if err != nil || metadata.Msg.Job.JobId != id {
						t.Errorf("view_jobs action=%s host=%s denied after save: %v", name, host, err)
					}
				} else if connect.CodeOf(err) != connect.CodePermissionDenied {
					t.Errorf("view_jobs action=%s host=%s error code=%v; want permission_denied", name, host, connect.CodeOf(err))
				}
				output, err := f.jobs.GetJobOutput(ctx, connect.NewRequest(&v1.GetJobOutputRequest{JobId: id, Hostname: host, Stream: v1.OutputStream_OUTPUT_STREAM_STDOUT}))
				if allow {
					if err != nil || !bytes.Equal(output.Msg.Data, f.output) || !output.Msg.OutputStored {
						t.Errorf("view_output action=%s host=%s did not return stored fixture output: %v", name, host, err)
					}
				} else if connect.CodeOf(err) != connect.CodePermissionDenied {
					t.Errorf("view_output action=%s host=%s error code=%v; want permission_denied", name, host, connect.CodeOf(err))
				}
			}
			action, err := f.catalog.GetAction(ctx, connect.NewRequest(&v1.GetActionRequest{Action: name}))
			if after && name == "read_action" {
				if err != nil || action.Msg.Action.Name != name {
					t.Errorf("view_catalog action=%s denied after save: %v", name, err)
				}
			} else if connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Errorf("view_catalog action=%s error code=%v; want permission_denied", name, connect.CodeOf(err))
			}
		}
	}
	assertViews(false)
	current, err := f.policy.GetPolicy(ctx, connect.NewRequest(&v1.GetPolicyRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	rules := proto.Clone(current.Msg.Policy.Rules).(*v1.PolicyRules)
	rules.Rules = append(rules.Rules,
		&v1.PolicyRule{Name: "inspector-resource-views", Roles: []string{"inspector"}, Operations: []string{"view_jobs", "view_output", "view_catalog"}, Actions: []string{"read_action"}, Risks: []string{"read"}, Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW})
	request := func(base uint64) *connect.Request[v1.TestPolicyRequest] {
		return connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: base, Candidate: &v1.TestPolicyRequest_Rules{Rules: rules}})
	}
	tested, err := f.policy.TestPolicy(ctx, request(1))
	if err != nil {
		t.Fatal(err)
	}
	// read_action only: view_jobs and view_output on dev, prod and the empty
	// host of a job without tasks (6), the action-less view_jobs and
	// view_output checks (2), plus the action-less catalog check and the
	// read_action catalog decision (2).
	if tested.Msg.Test.ChangedCount != 10 {
		t.Errorf("default resource-view changes=%d; want 6 action job/output, 2 global job/output and 2 catalog decisions", tested.Msg.Test.ChangedCount)
	}
	const evaluations = 68 // S=2, C=12, H=2, A=2: S*(C+2H+3A+3AH).
	if tested.Msg.Test.EvaluatedCount != evaluations {
		t.Errorf("default resource-view evaluated=%d; want %d", tested.Msg.Test.EvaluatedCount, evaluations)
	}
	changes, err := f.policy.GetPolicyTestChanges(ctx, connect.NewRequest(&v1.GetPolicyTestChangesRequest{TestId: tested.Msg.Test.TestId}))
	if err != nil {
		t.Fatal(err)
	}
	hosts, empty := map[string]int{}, 0
	indices := map[uint32]bool{}
	for _, change := range changes.Msg.Changes {
		if change.Before.Effect != v1.PolicyEffect_POLICY_EFFECT_DENY || change.After.Effect != v1.PolicyEffect_POLICY_EFFECT_ALLOW || indices[change.CaseIndex] {
			t.Errorf("unexpected resource-view decision transition")
		}
		indices[change.CaseIndex] = true
		if change.Host == "" {
			empty++
		} else {
			hosts[change.Host]++
		}
	}
	// Empty host: view_jobs and view_output for read_action (2), the
	// action-less view_jobs and view_output checks (2), the action-less
	// catalog check and the read_action catalog decision (2).
	if hosts["dev"] != 2 || hosts["prod"] != 2 || len(hosts) != 2 || empty != 6 {
		t.Errorf("resource-view changed hosts=%v empty-host inputs=%d; want dev=2 prod=2, 6", hosts, empty)
	}
	explicit := request(1)
	explicit.Msg.Cases = []*v1.PolicyTestCase{
		{SubjectId: "inspector", Operation: "view_jobs", Action: "read_action", Targets: &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"prod"}}}}},
		{SubjectId: "inspector", Operation: "view_output", Action: "read_action", Targets: &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"prod"}}}}},
		{SubjectId: "inspector", Operation: "view_catalog", Action: "read_action"},
	}
	explicitResult, err := f.policy.TestPolicy(ctx, explicit)
	if err != nil {
		t.Fatal(err)
	}
	if explicitResult.Msg.Test.EvaluatedCount != 3 || explicitResult.Msg.Test.ChangedCount != 3 {
		t.Errorf("explicit view cases with case action evaluated=%d changed=%d; want 3,3", explicitResult.Msg.Test.EvaluatedCount, explicitResult.Msg.Test.ChangedCount)
	}
	if _, err = f.policy.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 1, Rules: rules, TestId: tested.Msg.Test.TestId})); err != nil {
		t.Fatal(err)
	}
	assertViews(true)
	f.identity.Config.MaxTestEvaluations = evaluations
	bounded, err := f.policy.TestPolicy(ctx, request(2))
	if err != nil {
		t.Fatal(err)
	}
	f.identity.Config.MaxTestEvaluations = evaluations - 1
	_, trialErr := f.policy.TestPolicy(ctx, request(2))
	_, saveErr := f.policy.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 2, Rules: rules, TestId: bounded.Msg.Test.TestId}))
	for operation, err := range map[string]error{"TestPolicy": trialErr, "SavePolicy": saveErr} {
		if connect.CodeOf(err) != connect.CodeResourceExhausted {
			t.Errorf("%s at evaluation limit code=%v; want resource_exhausted", operation, connect.CodeOf(err))
		}
		var limitError *connect.Error
		if !errors.As(err, &limitError) || limitError.Message() != "policy evaluation limit exceeded" {
			t.Errorf("%s at evaluation limit error=%v; want policy evaluation limit exceeded", operation, err)
		}
	}
	if connect.CodeOf(saveErr) != connect.CodeResourceExhausted {
		return
	}
	f.identity.Config.MaxTestEvaluations = evaluations
	if _, err = f.policy.SavePolicy(ctx, connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: 2, Rules: rules, TestId: bounded.Msg.Test.TestId})); err != nil {
		t.Fatal(err)
	}
}

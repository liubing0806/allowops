package store

import (
	"bytes"
	"context"
	"testing"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/testpg"
	"google.golang.org/protobuf/proto"
)

func TestApprovalMigrationUpgradeAndDowngrade(t *testing.T) {
	ctx := context.Background()
	dsn := testpg.Start(t)
	provider, closeDB, err := migrationProvider(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()
	if _, err := provider.UpTo(ctx, 9); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	exec := func(sql string) {
		t.Helper()
		if _, err := s.Pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO console_users(user_id,provider_id,provider_subject,kind,username) VALUES ('owner','test','owner','oidc','owner');
		INSERT INTO service_accounts(account_id,name,owner_user_id) VALUES ('svc','svc','owner');
		INSERT INTO service_account_tokens(token_id,account_id,token_hash,expires_at) VALUES ('legacy','svc',decode(repeat('ab',32),'hex'),now()+interval '1 hour');`)
	if _, err := provider.UpTo(ctx, SchemaVersion); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckSchema(ctx); err != nil {
		t.Fatal(err)
	}
	legacy, err := s.Queries.TouchServiceAccountToken(ctx, bytes.Repeat([]byte{0xab}, 32))
	if err != nil || legacy.AccountID != "svc" || legacy.TokenID != "legacy" || legacy.CreatedByUserID != "" {
		t.Fatalf("legacy token metadata=%+v err=%v", legacy, err)
	}
	var indexes int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_indexes
		WHERE (indexname='jobs_pending_approval' AND indexdef LIKE '%WHERE%status%8%')
		   OR (indexname='approval_requests_client_request' AND indexdef LIKE '%UNIQUE%WHERE%client_request_id%')`).Scan(&indexes); err != nil || indexes != 2 {
		t.Fatalf("approval partial indexes=%d err=%v", indexes, err)
	}
	exec(`INSERT INTO gateway_instances(instance_id,version) VALUES ('gateway','test');
		INSERT INTO jobs(job_id,created_at,subject_id,origin_instance,action,action_definition,catalog_id,catalog_version,action_sha256,policy_version,reason,status,batch_size,max_failures)
		VALUES ('pending',now(),'svc','gateway','test','{}','test',1,decode(repeat('00',32),'hex'),1,'test',8,1,0);
		INSERT INTO hosts(host_id,hostname,certificate_serial,certificate_expires_at) VALUES ('host','host','test',now()+interval '1 hour');
		CREATE TABLE tasks_fixture PARTITION OF tasks DEFAULT;
		INSERT INTO tasks(job_id, task_id, created_at, host_id, hostname, position, status, result)
			SELECT job_id, 'task', created_at, 'host', 'host', 0, 1, decode('0801','hex') FROM jobs WHERE job_id='pending';`)
	if _, err := provider.DownTo(ctx, 9); err != nil {
		t.Fatal(err)
	}
	var state int
	if err := s.Pool.QueryRow(ctx, "SELECT status FROM jobs WHERE job_id='pending' AND finished_at IS NOT NULL").Scan(&state); err != nil || state != 7 {
		t.Fatalf("downgraded pending job status=%d err=%v", state, err)
	}
	var taskState int
	var output string
	var result []byte
	err = s.Pool.QueryRow(ctx, "SELECT status,output_state,result FROM tasks WHERE task_id='task' AND finished_at IS NOT NULL").Scan(&taskState, &output, &result)
	decoded := &v1.ExecutionResult{}
	if err != nil || taskState != 8 || output != "unavailable" || proto.Unmarshal(result, decoded) != nil || decoded.Status != v1.TaskStatus_TASK_STATUS_CANCELLED {
		t.Fatalf("downgraded task status=%d output=%s result=%v err=%v", taskState, output, decoded, err)
	}

	if _, err := provider.UpTo(ctx, SchemaVersion); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckSchema(ctx); err != nil {
		t.Fatal(err)
	}
}

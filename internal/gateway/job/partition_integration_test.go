package job_test

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/store"
)

func TestRestrictedRuntimeJobPartitions(t *testing.T) {
	ctx := context.Background()
	var maintenance *store.Store
	f := setup(t, func(f *fixture) {
		maintenance = f.DB
		if _, err := maintenance.Pool.Exec(ctx, `
			CREATE ROLE job_runtime_fixture LOGIN PASSWORD 'local-fixture-only';
			GRANT CONNECT ON DATABASE fixture TO job_runtime_fixture;
			GRANT USAGE ON SCHEMA public TO job_runtime_fixture;
			GRANT allowops_audit_writer, allowops_job_writer TO job_runtime_fixture;
			GRANT SELECT ON goose_db_version, roles TO job_runtime_fixture;
			GRANT SELECT, INSERT, UPDATE ON gateway_instances, hosts, host_catalog_reports, join_tokens, catalog_versions,
			    console_users, service_accounts, service_account_tokens
			    TO job_runtime_fixture;
			GRANT SELECT, INSERT, UPDATE, DELETE ON gateway_messages, host_import_previews, catalog_uploads,
			    identity_sessions, policy_tests, oidc_transactions, cli_login_codes
			    TO job_runtime_fixture;
			GRANT SELECT, INSERT, DELETE ON role_mappings TO job_runtime_fixture;
			GRANT SELECT, INSERT ON policy_versions TO job_runtime_fixture;
			GRANT SELECT, UPDATE ON role_mapping_state TO job_runtime_fixture;
		`); err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(f.DSN)
		if err != nil {
			t.Fatal(err)
		}
		u.User = url.UserPassword("job_runtime_fixture", "local-fixture-only")
		runtime, err := store.Open(ctx, u.String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(runtime.Close)
		f.DB = runtime
	})

	month := time.Now().UTC()
	current := pgx.Identifier{month.Format("tasks_200601")}.Sanitize()
	if _, err := f.DB.Pool.Exec(ctx, "SELECT 1 FROM "+current); err != nil {
		t.Fatalf("read migration-created partition: %v", err)
	}
	if _, err := f.DB.Pool.Exec(ctx, "UPDATE oidc_transactions SET binding_hash=NULL WHERE false"); err != nil {
		t.Fatalf("update oidc_transactions as restricted role: %v", err)
	}
	for _, fn := range []struct {
		name string
		run  func(context.Context, int32) error
	}{
		{"policy_tests", f.DB.Queries.DeleteExpiredPolicyTestBatch},
		{"cli_login_codes", f.DB.Queries.DeleteExpiredCliLoginCodeBatch},
		{"oidc_transactions", f.DB.Queries.DeleteExpiredOidcTransactionBatch},
		{"identity_sessions", f.DB.Queries.DeleteOldIdentitySessionBatch},
	} {
		if err := fn.run(ctx, 10); err != nil {
			t.Fatalf("expired %s cleanup as restricted role: %v", fn.name, err)
		}
	}
	for _, sql := range []string{
		"SELECT tasks_create_partitions(now(), 3)",
		"CREATE TABLE tasks_ddl_fixture PARTITION OF tasks DEFAULT",
		"ALTER TABLE tasks DETACH PARTITION " + current,
	} {
		_, err := f.DB.Pool.Exec(ctx, sql)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("%s: %v; want permission denied (42501)", sql, err)
		}
	}

	if _, err := maintenance.Pool.Exec(ctx, "ALTER TABLE tasks DETACH PARTITION "+current+"; DROP TABLE "+current); err != nil {
		t.Fatal(err)
	}
	_, err := f.A.Client.RunJob(ctx, connect.NewRequest(request("stable")))
	var rpcErr *connect.Error
	if !errors.As(err, &rpcErr) || rpcErr.Code() != connect.CodeUnavailable || rpcErr.Message() != "TASK_PARTITION_MISSING" {
		t.Fatalf("run job with no current partition: %v; want Unavailable/TASK_PARTITION_MISSING", err)
	}
	var count int
	if err := f.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM jobs").Scan(&count); err != nil || count != 0 {
		t.Fatalf("jobs after missing partition: count=%d err=%v; want 0 rows", count, err)
	}
	if _, err := maintenance.Pool.Exec(ctx, "SELECT tasks_create_partitions(now(), 3)"); err != nil {
		t.Fatalf("create partition as maintenance role: %v", err)
	}

	res := run(t, f.A, request("stable"))
	if got := get(t, f.A, res.Job.JobId).Job.Status; got != v1.JobStatus_JOB_STATUS_SUCCEEDED {
		t.Fatalf("job status=%v; want SUCCEEDED", got)
	}
	list := tasks(t, f.A, res.Job.JobId)
	if len(list) != 3 {
		t.Fatalf("task count=%d; want 3", len(list))
	}
	for _, task := range list {
		if task.Result.Status != v1.TaskStatus_TASK_STATUS_SUCCEEDED {
			t.Errorf("task %s status=%v; want SUCCEEDED", task.TaskId, task.Result.Status)
		}
	}
	awaitFixtureOutputs(t, f)
}

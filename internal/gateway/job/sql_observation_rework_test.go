package job_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"google.golang.org/protobuf/proto"
)

type schedulerLogBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *schedulerLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}
func (b *schedulerLogBuffer) snapshot() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.String()
}
func schedulerRecords(t *testing.T, b *schedulerLogBuffer, id, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(b.snapshot()), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record["job_id"] == id && record["msg"] == msg {
			out = append(out, record)
		}
	}
	return out
}

func TestSchedulerSQLFailureObservation(t *testing.T) {
	f := setup(t)
	t.Cleanup(func() { awaitFixtureOutputs(t, f) })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := f.DB.Pool.Exec(ctx, `CREATE SEQUENCE rf_observe_attempt;
      CREATE FUNCTION rf_observe_sql() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NEW.reason='rf-observe-transient' AND NEW.status=2 AND OLD.status=1 AND nextval('rf_observe_attempt')<=3 THEN
          RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='rf-private-sql-sentinel',DETAIL='rf-private-dsn-sentinel',HINT='rf-private-parameter-sentinel';
        END IF;
        IF NEW.reason='rf-observe-permanent' AND NEW.status>2 THEN
          RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='rf-private-sql-sentinel',DETAIL='rf-private-dsn-sentinel',HINT='rf-private-parameter-sentinel';
        END IF;
        RETURN NEW;
      END $$;
      CREATE TRIGGER rf_observe_sql BEFORE UPDATE ON jobs FOR EACH ROW EXECUTE FUNCTION rf_observe_sql()`); err != nil {
		t.Fatal(err)
	}
	var captured schedulerLogBuffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&captured, nil)))
	t.Cleanup(func() { slog.SetDefault(original) })
	// Remove only this fixture's trigger and unfinished job before service cleanup.
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		if _, err := f.DB.Pool.Exec(cleanup, `DROP TRIGGER rf_observe_sql ON jobs;UPDATE jobs SET status=4 WHERE reason='rf-observe-permanent' AND status IN(1,2)`); err != nil {
			t.Error(err)
		}
	})
	for _, mode := range []string{"transient", "permanent"} {
		t.Run(mode, func(t *testing.T) {
			r := request("stable")
			r.Reason = "rf-observe-" + mode
			r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"a-host"}}}}
			r.ExpectedCount = nil
			r.WaitSeconds = proto.Uint32(0)
			id := run(t, f.A, r).Job.JobId
			message, wantState := "job SQL retrying", "40001"
			if mode == "transient" {
				eventually(t, func() bool {
					var status int16
					err := f.DB.Pool.QueryRow(ctx, "SELECT status FROM jobs WHERE job_id=$1", id).Scan(&status)
					return err == nil && status == 3
				})
				var attempts int
				if err := f.DB.Pool.QueryRow(ctx, "SELECT last_value FROM rf_observe_attempt").Scan(&attempts); err != nil {
					t.Fatal(err)
				}
				if attempts != 4 {
					t.Fatalf("SQL attempts=%d; want three real rollback failures then success", attempts)
				}
			} else {
				message, wantState = "job scheduler stopped", "42501"
				eventually(t, func() bool { return len(schedulerRecords(t, &captured, id, message)) > 0 })
				var status int16
				if err := f.DB.Pool.QueryRow(ctx, "SELECT status FROM jobs WHERE job_id=$1", id).Scan(&status); err != nil {
					t.Fatal(err)
				}
				if status != 2 {
					t.Errorf("permanent error status=%d; accepted scope preserves RUNNING(2)", status)
				}
			}
			records := schedulerRecords(t, &captured, id, message)
			if len(records) != 1 {
				t.Errorf("safe observation count=%d for %s; want 1", len(records), mode)
			}
			for _, record := range records {
				if record["sqlstate"] != wantState || record["error_type"] != "*pgconn.PgError" {
					t.Errorf("safe error classification sqlstate=%v error_type=%v; want %s,*pgconn.PgError", record["sqlstate"], record["error_type"], wantState)
				}
			}
			if strings.Contains(captured.snapshot(), "rf-private-") {
				t.Error("SQL observation leaked private error message/detail/hint")
			}
		})
	}
}

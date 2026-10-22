package job_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"google.golang.org/protobuf/proto"
)

// stableOutputJob runs a finished job on a-host and waits until its output has
// been persisted, so later assertions do not race the persistence goroutine.
func stableOutputJob(t *testing.T, f *fixture) string {
	t.Helper()
	r := request("stable")
	r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"a-host"}}}}
	r.ExpectedCount = nil
	r.WaitSeconds = proto.Uint32(5)
	id := run(t, f.A, r).Job.JobId
	eventually(t, func() bool {
		list := tasks(t, f.B, id)
		return len(list) == 1 && list[0].OutputStored
	})
	return id
}

func TestTerminalTaskRecordsTheInstanceOwningItsOutput(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	id := stableOutputJob(t, f)
	var owner *string
	if err := f.DB.Pool.QueryRow(ctx, "SELECT output_instance FROM tasks WHERE job_id=$1", id).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	// The agent of a-host is connected to gateway A, which receives its result.
	if owner == nil || *owner != f.A.Host.InstanceID {
		t.Fatalf("output_instance=%v; want %s", owner, f.A.Host.InstanceID)
	}
}

// A gateway that dies after the terminal COMMIT and before persistence ends
// leaves output_state pending. Once the owner is lost, recovery by another
// gateway must make the output unavailable instead of leaving it pending.
func TestPendingOutputOfLostInstanceBecomesUnavailable(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	lostJob, liveJob := stableOutputJob(t, f), stableOutputJob(t, f)
	if _, err := f.DB.Pool.Exec(ctx, "INSERT INTO gateway_instances(instance_id,last_seen) VALUES ('crashed',now()-interval '1 hour')"); err != nil {
		t.Fatal(err)
	}
	for job, owner := range map[string]string{lostJob: "crashed", liveJob: f.A.Host.InstanceID} {
		if _, err := f.DB.Pool.Exec(ctx, "UPDATE tasks SET output_state='pending',output_stored=false,output_instance=$2 WHERE job_id=$1", job, owner); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.B.Job.RecoverLostInstances(ctx); err != nil {
		t.Fatal(err)
	}
	// Each gateway's own recovery loop races this call: a pass that finds the
	// row locked by another survivor skips it, and that commit lands later.
	eventually(t, func() bool {
		var state string
		return f.DB.Pool.QueryRow(ctx, "SELECT output_state FROM tasks WHERE job_id=$1", lostJob).Scan(&state) == nil && state == "unavailable"
	})
	for _, c := range []struct{ job, want string }{{lostJob, "unavailable"}, {liveJob, "pending"}} {
		var state string
		if err := f.DB.Pool.QueryRow(ctx, "SELECT output_state FROM tasks WHERE job_id=$1", c.job).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if state != c.want {
			t.Errorf("job %s output_state=%s; want %s", c.job, state, c.want)
		}
	}
	var reason string
	var audits int
	if err := f.DB.Pool.QueryRow(ctx, "SELECT count(*),COALESCE(max(reason),'') FROM audit_events WHERE operation='store_output' AND job_id=$1 AND decision='deny'", lostJob).Scan(&audits, &reason); err != nil {
		t.Fatal(err)
	}
	if audits != 1 || reason != "OUTPUT_INSTANCE_LOST" {
		t.Errorf("store_output deny audits=%d reason=%q; want 1,OUTPUT_INSTANCE_LOST", audits, reason)
	}
	_, err := f.B.Client.GetJobOutput(ctx, connect.NewRequest(&v1.GetJobOutputRequest{JobId: lostJob, Hostname: "a-host", Stream: v1.OutputStream_OUTPUT_STREAM_STDOUT}))
	var detail *v1.ErrorDetail
	if rpcErr, ok := err.(*connect.Error); ok {
		for _, item := range rpcErr.Details() {
			if value, _ := item.Value(); value != nil {
				if d, ok := value.(*v1.ErrorDetail); ok {
					detail = d
				}
			}
		}
	}
	if connect.CodeOf(err) != connect.CodeNotFound || detail == nil || detail.Reason != "OUTPUT_UNAVAILABLE" || detail.RetryAfter != nil {
		t.Errorf("output read error=%v detail=%v; want NOT_FOUND/OUTPUT_UNAVAILABLE without retry", err, detail)
	}
	// A second pass finds nothing left to recover and appends no further audit.
	if err := f.B.Job.RecoverLostInstances(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE operation='store_output' AND job_id=$1 AND decision='deny'", lostJob).Scan(&audits); err != nil || audits != 1 {
		t.Errorf("repeated recovery store_output deny audits=%d error=%v; want 1", audits, err)
	}
}

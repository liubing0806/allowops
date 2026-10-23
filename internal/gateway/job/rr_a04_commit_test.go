package job_test

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/store"
	"google.golang.org/protobuf/proto"
)

// commitLossProxy is a TCP proxy in front of PostgreSQL. After it sees the armed
// statement on a connection it forwards that connection's next simple-protocol
// COMMIT to the server, waits for the server's reply, drops the reply and closes
// the client side. PostgreSQL has committed, the client sees only a lost
// connection: a COMMIT error that does not mean rollback.
type commitLossProxy struct {
	listener net.Listener
	upstream string
	arm      []byte
	fired    atomic.Bool
	// withhold makes the proxy drop the armed COMMIT instead of forwarding it:
	// the server never receives it and rolls the transaction back on disconnect.
	withhold atomic.Bool
	// outage, when set before the proxy fires, also ends every other proxied
	// connection when the COMMIT reply is dropped and refuses new connections
	// for that long: the database is briefly unreachable, so a follow-up read
	// that checks whether the COMMIT landed fails as well.
	outage      time.Duration
	refuseUntil atomic.Int64
	mu          sync.Mutex
	conns       map[net.Conn]bool
}

var simpleCommit = []byte("Q\x00\x00\x00\x0bcommit\x00")

func newCommitLossProxy(t *testing.T, db *store.Store, armStatement string) *commitLossProxy {
	t.Helper()
	cfg := db.Pool.Config().ConnConfig
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &commitLossProxy{listener: listener, upstream: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), arm: []byte(armStatement), conns: map[net.Conn]bool{}}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			if time.Now().UnixNano() < p.refuseUntil.Load() {
				client.Close()
				continue
			}
			go p.handle(client)
		}
	}()
	return p
}

func (p *commitLossProxy) handle(client net.Conn) {
	server, err := net.Dial("tcp", p.upstream)
	if err != nil {
		client.Close()
		return
	}
	p.mu.Lock()
	p.conns[client] = true
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.conns, client)
		p.mu.Unlock()
	}()
	var drop atomic.Bool
	go func() {
		defer client.Close()
		defer server.Close()
		buf := make([]byte, 32<<10)
		for {
			n, err := server.Read(buf)
			if n > 0 {
				if drop.Load() {
					return
				}
				if _, werr := client.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	defer server.Close()
	buf := make([]byte, 32<<10)
	var tail []byte
	armed := false
	for {
		n, err := client.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if !armed && bytes.Contains(append(append([]byte{}, tail...), chunk...), p.arm) {
				armed = true
				chunk = nil // the armed statement is never the COMMIT
			}
			tail = append(tail[:0], buf[max(0, n-len(p.arm)):n]...)
			if armed && bytes.Contains(chunk, simpleCommit) && p.fired.CompareAndSwap(false, true) {
				if p.withhold.Load() {
					client.Close()
					return
				}
				drop.Store(true)
				if p.outage > 0 {
					p.refuseUntil.Store(time.Now().Add(p.outage).UnixNano())
					p.mu.Lock()
					for c := range p.conns {
						if c != client {
							c.Close()
						}
					}
					p.mu.Unlock()
				}
			}
			if _, werr := server.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// proxiedJobStore builds the job service pool during fixture configuration,
// before the services start, so no running service observes a replaced Store.
func proxiedJobStore(t *testing.T, db *store.Store, p *commitLossProxy) *store.Store {
	t.Helper()
	cfg := db.Pool.Config()
	host, port, err := net.SplitHostPort(p.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	number, _ := strconv.Atoi(port)
	cfg.ConnConfig.Host, cfg.ConnConfig.Port = host, uint16(number)
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	proxied := *db
	proxied.Pool = pool
	return &proxied
}

// RR-a-04 and OR-a N-03: a COMMIT error is not a rollback. When the server has
// committed and only the reply was lost, the gateway must treat the write as
// committed instead of abandoning the follow-up work.
func TestRRA04CommitErrorAfterServerCommit(t *testing.T) {
	for _, mode := range []string{"terminal_result_commit", "job_create_commit"} {
		t.Run(mode, func(t *testing.T) {
			var proxy *commitLossProxy
			f := setup(t, func(f *fixture) {
				if mode == "terminal_result_commit" {
					proxy = newCommitLossProxy(t, f.DB, "finished_at=now(),stdout_preview=")
				} else {
					proxy = newCommitLossProxy(t, f.DB, "INSERT INTO jobs(job_id")
				}
				proxied := proxiedJobStore(t, f.DB, proxy)
				f.BeforeStart = func(_ *hostconn.Service, jobs *job.Service) {
					// A owns the host connection and processes task events; B creates jobs.
					if (mode == "terminal_result_commit" && f.A == nil) || (mode == "job_create_commit" && f.A != nil && f.B == nil) {
						jobs.Store = proxied
					}
				}
			})
			t.Cleanup(func() { awaitFixtureOutputs(t, f) })
			r := request("stable")
			r.Reason = "rr-a-04-" + mode
			r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"a-host"}}}}
			r.ExpectedCount = nil
			r.WaitSeconds = proto.Uint32(0)
			response, err := f.B.Client.RunJob(context.Background(), connect.NewRequest(r))
			if !proxy.fired.Load() && mode == "job_create_commit" {
				t.Fatalf("fixture did not lose the COMMIT reply; RunJob error=%v", err)
			}
			if err != nil {
				t.Fatalf("RunJob after server-side COMMIT with lost reply: %v; want committed job", err)
			}
			id := response.Msg.Job.JobId
			var jobStatus, taskStatus int16
			var state string
			end := time.Now().Add(10 * time.Second)
			for {
				if err := f.DB.Pool.QueryRow(context.Background(), "SELECT j.status,t.status,t.output_state FROM jobs j JOIN tasks t USING (job_id) WHERE j.job_id=$1", id).Scan(&jobStatus, &taskStatus, &state); err != nil {
					t.Fatal(err)
				}
				if (jobStatus > 2 && state != "pending") || time.Now().After(end) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !proxy.fired.Load() {
				t.Fatal("fixture did not lose the COMMIT reply")
			}
			if jobStatus != int16(v1.JobStatus_JOB_STATUS_SUCCEEDED) || taskStatus != int16(v1.TaskStatus_TASK_STATUS_SUCCEEDED) || state != "stored" {
				t.Errorf("job=%d task=%d output_state=%s; want SUCCEEDED(3), SUCCEEDED(3), stored", jobStatus, taskStatus, state)
			}
		})
	}
}

// RR-a-04 reverse case: when the COMMIT never reaches the server, the transaction
// is rolled back. The COMMIT error must then stay an error: terminal handling must
// not start output persistence for the rolled-back attempt, and job creation must
// return the error with no job row. A check that always reports "committed" fails
// this test.
func TestRRA04CommitNeverReachesServer(t *testing.T) {
	for _, mode := range []string{"terminal_result_commit", "job_create_commit"} {
		t.Run(mode, func(t *testing.T) {
			var proxy *commitLossProxy
			f := setup(t, func(f *fixture) {
				if mode == "terminal_result_commit" {
					proxy = newCommitLossProxy(t, f.DB, "finished_at=now(),stdout_preview=")
				} else {
					proxy = newCommitLossProxy(t, f.DB, "INSERT INTO jobs(job_id")
				}
				proxy.withhold.Store(true)
				proxied := proxiedJobStore(t, f.DB, proxy)
				f.BeforeStart = func(_ *hostconn.Service, jobs *job.Service) {
					if (mode == "terminal_result_commit" && f.A == nil) || (mode == "job_create_commit" && f.A != nil && f.B == nil) {
						jobs.Store = proxied
					}
				}
			})
			reason := "rr-a-04-withheld-" + mode
			r := request("stable")
			r.Reason = reason
			r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"a-host"}}}}
			r.ExpectedCount = nil
			r.WaitSeconds = proto.Uint32(0)
			response, err := f.B.Client.RunJob(context.Background(), connect.NewRequest(r))
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if mode == "job_create_commit" {
				if !proxy.fired.Load() {
					t.Fatalf("fixture did not withhold the COMMIT; RunJob error=%v", err)
				}
				if err == nil {
					t.Fatalf("RunJob returned job %s after a COMMIT that never reached the server; want error", response.Msg.Job.JobId)
				}
				// The error must be the COMMIT failure itself. A job treated as
				// committed would instead fail later, when reading the absent row.
				t.Logf("RunJob error=%v", err)
				if connect.CodeOf(err) == connect.CodeNotFound {
					t.Fatalf("RunJob error=%v; want the COMMIT failure, not a missing job lookup", err)
				}
				var n int
				if err := f.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM jobs WHERE reason=$1", reason).Scan(&n); err != nil {
					t.Fatal(err)
				}
				if n != 0 {
					t.Errorf("jobs with reason %q=%d; want 0 after rollback", reason, n)
				}
				return
			}
			if err != nil {
				t.Fatalf("RunJob: %v", err)
			}
			id := response.Msg.Job.JobId
			end := time.Now().Add(10 * time.Second)
			for !proxy.fired.Load() && time.Now().Before(end) {
				time.Sleep(10 * time.Millisecond)
			}
			if !proxy.fired.Load() {
				t.Fatal("fixture did not withhold the terminal COMMIT")
			}
			// The withheld COMMIT rolled the first attempt back, and the gateway
			// must not treat it as committed: output is never stored while the
			// task row is still running. The event transaction is then retried on
			// a new connection, which commits the agent result and persists the
			// output exactly once. The host connection stays open.
			var taskStatus int16
			var state string
			until := time.Now().Add(10 * time.Second)
			for {
				if err := f.DB.Pool.QueryRow(context.Background(), "SELECT status,output_state FROM tasks WHERE job_id=$1", id).Scan(&taskStatus, &state); err != nil {
					t.Fatal(err)
				}
				if state == "stored" && taskStatus <= 2 {
					t.Fatalf("output_state=stored while task status=%d; the rolled-back terminal write was treated as committed", taskStatus)
				}
				if (taskStatus > 2 && state != "pending") || time.Now().After(until) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if taskStatus != int16(v1.TaskStatus_TASK_STATUS_SUCCEEDED) || state != "stored" {
				t.Fatalf("task=%d output_state=%s after the retried terminal write; want SUCCEEDED(3), stored", taskStatus, state)
			}
			// persist appends the store_output audit event after the output_state
			// write: wait for the first event, then watch briefly for a second one.
			count := func() (n int) {
				if err := f.DB.Pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_events WHERE operation='store_output'").Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			stored := count()
			for until := time.Now().Add(5 * time.Second); stored == 0 && time.Now().Before(until); stored = count() {
				time.Sleep(10 * time.Millisecond)
			}
			for until := time.Now().Add(500 * time.Millisecond); stored == 1 && time.Now().Before(until); stored = count() {
				time.Sleep(10 * time.Millisecond)
			}
			if stored != 1 {
				t.Fatalf("store_output audit events=%d; want 1 from the retried terminal write", stored)
			}
		})
	}
}

// The terminal COMMIT lands but its reply is lost, and the database stays
// unreachable long enough that the follow-up check of the task row fails too.
// The event is then retried as a replay that finds the task already terminal
// with this very result. That replay must start output persistence: the
// receiving instance is alive, so lost-instance recovery never ends the
// pending output.
func TestTerminalReplayAfterLostCommitAndFailedCheck(t *testing.T) {
	var proxy *commitLossProxy
	f := setup(t, func(f *fixture) {
		proxy = newCommitLossProxy(t, f.DB, "finished_at=now(),stdout_preview=")
		proxy.outage = 500 * time.Millisecond
		proxied := proxiedJobStore(t, f.DB, proxy)
		f.BeforeStart = func(_ *hostconn.Service, jobs *job.Service) {
			if f.A == nil {
				jobs.Store = proxied
			}
		}
	})
	t.Cleanup(func() { awaitFixtureOutputs(t, f) })
	r := request("stable")
	r.Reason = "terminal-replay-lost-commit"
	r.Targets = &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: []string{"a-host"}}}}
	r.ExpectedCount = nil
	r.WaitSeconds = proto.Uint32(0)
	response, err := f.B.Client.RunJob(context.Background(), connect.NewRequest(r))
	if err != nil {
		t.Fatalf("RunJob: %v", err)
	}
	id := response.Msg.Job.JobId
	var taskStatus int16
	var state string
	end := time.Now().Add(15 * time.Second)
	for {
		if err := f.DB.Pool.QueryRow(context.Background(), "SELECT status,output_state FROM tasks WHERE job_id=$1", id).Scan(&taskStatus, &state); err != nil {
			t.Fatal(err)
		}
		if (taskStatus > 2 && state != "pending") || time.Now().After(end) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !proxy.fired.Load() {
		t.Fatal("fixture did not lose the terminal COMMIT reply")
	}
	if taskStatus != int16(v1.TaskStatus_TASK_STATUS_SUCCEEDED) || state != "stored" {
		t.Fatalf("task=%d output_state=%s after a replayed terminal result; want SUCCEEDED(3), stored", taskStatus, state)
	}
}

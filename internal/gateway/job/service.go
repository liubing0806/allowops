package job

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/output"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"github.com/liubing0806/allowops/internal/store"
	"google.golang.org/protobuf/proto"
)

// AccessChecker is the part of the management API the job service uses for
// request checks and authorization. *api.Service implements it.
type AccessChecker interface {
	// Middleware authenticates requests and stores the caller in the context.
	Middleware(http.Handler) http.Handler
	// CheckRequest applies the transport checks (TLS, origin, CSRF).
	CheckRequest(ctx context.Context, write bool) error
	// RequireBatch authorizes one operation against several hosts.
	RequireBatch(ctx context.Context, op authz.Operation, action authz.Action, hosts []authz.Host) ([]authz.HostResult, uint64, error)
}

type Service struct {
	Store                       *store.Store
	Access                      AccessChecker
	Router                      hostconn.Router
	Storage                     output.Storage
	Audit                       audit.Appender
	Trusted                     map[string]ed25519.PublicKey
	Config                      Config
	Previews                    PreviewSource
	ctx                         context.Context
	cancel                      context.CancelFunc
	wg                          sync.WaitGroup
	mu                          sync.Mutex
	outputs                     map[string]*taskOutput
	dispatches                  map[string]context.CancelFunc
	cancelWorkers               map[string]bool // job ID -> running; false after an unrecoverable stop
	instanceID                  string
	lostAfter, recoveryInterval time.Duration
	started, draining           atomic.Bool
	activeJobs                  atomic.Int64
	activePersists              atomic.Int64
	submitMu                    sync.Mutex
}

func New(db *store.Store, access AccessChecker, router hostconn.Router, storage output.Storage, auditor audit.Appender, trusted map[string]ed25519.PublicKey, c Config) (*Service, error) {
	if db == nil || access == nil || router == nil || storage == nil || auditor == nil {
		return nil, errors.New("job dependencies required")
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	owner, ok := router.(*hostconn.Service)
	if !ok {
		return nil, errors.New("job router instance metadata required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{Store: db, Access: access, Router: router, Storage: storage, Audit: auditor, Trusted: trusted, Config: c, ctx: ctx, cancel: cancel, outputs: map[string]*taskOutput{}, dispatches: map[string]context.CancelFunc{}, cancelWorkers: map[string]bool{}}
	s.Previews = &DatabasePreviews{Store: db}
	s.instanceID = owner.InstanceID
	s.lostAfter = hostconn.InstanceLostAfter(owner.Config)
	s.recoveryInterval = min(owner.Config.CleanupInterval, s.lostAfter/2)
	return s, nil
}

func (s *Service) Close() {
	s.mu.Lock()
	s.cancel()
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Service) clearTasks(jobID string, taskIDs ...string) {
	if len(taskIDs) == 0 {
		return
	}
	s.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(taskIDs))
	outs := make([]*taskOutput, 0, len(taskIDs))
	for _, taskID := range taskIDs {
		key := outputID(jobID, taskID)
		if cancel := s.dispatches[key]; cancel != nil {
			delete(s.dispatches, key)
			cancels = append(cancels, cancel)
		}
		if out := s.outputs[key]; out != nil {
			outs = append(outs, out)
		}
	}
	s.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	for _, out := range outs {
		out.mu.Lock()
		//lint:ignore SA2001 Wait for the current output critical section before removing the buffer.
		out.mu.Unlock()
	}
	s.mu.Lock()
	for _, taskID := range taskIDs {
		delete(s.outputs, outputID(jobID, taskID))
	}
	s.mu.Unlock()
}

type operationKey struct{}

type operationState struct {
	JobID                               string
	Version                             uint64
	Rules                               []string
	Committed, AuthorizationAuditFailed bool
}

func operationInfo(ctx context.Context) *operationState {
	state, _ := ctx.Value(operationKey{}).(*operationState)
	return state
}

func (s *Service) audit(ctx context.Context, op, phase, outcome, jobID string, version uint64, rules []string) error {
	actor, ip := reqctx.RequestInfo(ctx)
	_, err := s.Audit.Append(ctx, audit.Payload{SubjectID: actor, SourceIP: ip, Operation: op, Reason: phase, Decision: outcome, JobID: jobID, PolicyVersion: version, MatchedRules: rules})
	if err != nil {
		if phase == "authorized" {
			if state := operationInfo(ctx); state != nil {
				state.AuthorizationAuditFailed = true
			}
		}
		return failure(connect.CodeUnavailable, "AUDIT_UNAVAILABLE")
	}
	return nil
}

// operation covers Connect and direct MCP-service calls with the same two audit phases, authorized then result (design P6M, G28).
func (s *Service) operation(ctx context.Context, op string, write bool, fn func(context.Context) (proto.Message, error)) (result proto.Message, err error) {
	state := &operationState{}
	ctx = context.WithValue(ctx, operationKey{}, state)
	defer func() {
		if state.AuthorizationAuditFailed {
			return
		}
		outcome := "deny"
		if err == nil {
			outcome = "allow"
		}
		resultCtx, cancelResult := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancelResult()
		if aerr := s.audit(resultCtx, op, "result", outcome, state.JobID, state.Version, state.Rules); aerr != nil {
			result = nil
			if state.Committed && write {
				err = failure(connect.CodeUnavailable, "AUDIT_RESULT_UNAVAILABLE")
			} else {
				err = aerr
			}
		}
	}()
	if err = s.Access.CheckRequest(ctx, write); err != nil {
		return nil, err
	}
	// Authorization-specific pre-write audit is performed after target ABAC by
	// RunJob/CancelJob; read operations need only the final phase.
	result, err = fn(ctx)
	return result, err
}

func (s *Service) RunJob(ctx context.Context, r *v1.RunJobRequest) (*v1.RunJobResponse, error) {
	m, err := s.operation(ctx, "run_job", true, func(ctx context.Context) (proto.Message, error) {
		if r == nil {
			return nil, failure(connect.CodeInvalidArgument, "REQUEST_REQUIRED")
		}
		if s.draining.Load() {
			return nil, failure(connect.CodeUnavailable, "GATEWAY_DRAINING")
		}
		f, err := format(r.ResponseFormat)
		if err != nil {
			return nil, err
		}
		wait, err := s.waitValue(r.WaitSeconds, s.Config.WaitSeconds)
		if err != nil {
			return nil, err
		}
		p, a, digest, err := s.action(ctx, r.Action)
		if err != nil {
			return nil, err
		}
		batch, failures, err := prepare(a, r, s.Config)
		if err != nil {
			return nil, err
		}
		all, err := s.hosts(ctx)
		if err != nil {
			return nil, failure(connect.CodeUnavailable, "HOST_DATABASE_UNAVAILABLE")
		}
		targets, err := selectTargets(all, r.Targets)
		if err != nil {
			return nil, err
		}
		if _, selector := r.Targets.Selection.(*v1.HostTargets_Selector); selector && r.ExpectedCount == nil {
			return nil, detailError(connect.CodeInvalidArgument, &v1.ErrorDetail{Reason: "EXPECTED_COUNT_REQUIRED", ActualCount: proto.Uint64(uint64(len(targets)))})
		}
		if r.ExpectedCount != nil && *r.ExpectedCount != uint64(len(targets)) {
			return nil, detailError(connect.CodeFailedPrecondition, &v1.ErrorDetail{Reason: "EXPECTED_COUNT_MISMATCH", ActualCount: proto.Uint64(uint64(len(targets)))})
		}
		if len(targets) == 0 {
			return nil, failure(connect.CodeInvalidArgument, "NO_TARGETS")
		}
		hosts := make([]authz.Host, len(targets))
		for i, h := range targets {
			hosts[i] = h.attributes()
		}
		decisions, version, err := s.Access.RequireBatch(ctx, authz.ExecuteAction, authz.Action{Name: a.Name, Risk: a.Risk}, hosts)
		if err != nil {
			return nil, err
		}
		denials := []*v1.HostDenial{}
		rules := []string{}
		for i, d := range decisions {
			rules = append(rules, d.Result.RuleIDs...)
			if d.Err != nil || d.Result.Decision != "allow" {
				denials = append(denials, &v1.HostDenial{Host: targets[i].Name, Rules: d.Result.RuleIDs})
			}
		}
		outcome := "allow"
		if len(denials) > 0 {
			outcome = "deny"
		}
		if err := s.audit(ctx, "run_job", "authorized", outcome, "", version, rules); err != nil {
			return nil, err
		}
		actor, _ := reqctx.RequestInfo(ctx)
		s.submitMu.Lock()
		if s.draining.Load() {
			s.submitMu.Unlock()
			return nil, failure(connect.CodeUnavailable, "GATEWAY_DRAINING")
		}
		j, err := s.create(ctx, actor, p, a, digest, r.Reason, targets, batch, failures, version, len(denials) > 0)
		if err != nil {
			s.submitMu.Unlock()
			return nil, err
		}
		state := operationInfo(ctx)
		state.JobID = j.JobId
		state.Version = version
		state.Rules = rules
		state.Committed = true
		if len(denials) > 0 {
			s.submitMu.Unlock()
			return nil, detailError(connect.CodePermissionDenied, &v1.ErrorDetail{Reason: "JOB_DENIED", DeniedHosts: denials, PolicyVersion: version, RequestId: j.JobId})
		}
		request := proto.Clone(r).(*v1.RunJobRequest)
		s.activeJobs.Add(1)
		s.wg.Add(1)
		go func(initial *v1.Job) {
			defer s.wg.Done()
			defer s.activeJobs.Add(-1)
			if err := s.schedule(s.ctx, initial, a, request, batch, failures); err != nil {
				logSQLFailure(s.ctx, slog.LevelError, "job scheduler stopped", initial.JobId, err)
			}
		}(j)
		s.submitMu.Unlock()
		j, err = s.wait(ctx, j.JobId, wait)
		if err != nil {
			return nil, err
		}
		summary, err := s.summary(ctx, j, f)
		if err != nil {
			return nil, err
		}
		return &v1.RunJobResponse{Job: j, Summary: summary}, nil
	})
	if err != nil {
		return nil, err
	}
	return m.(*v1.RunJobResponse), nil
}

func (s *Service) wait(ctx context.Context, id string, seconds uint32) (*v1.Job, error) {
	deadline := time.NewTimer(time.Duration(seconds) * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(pollInterval)
	defer tick.Stop()
	for {
		j, err := s.get(ctx, id)
		if err != nil {
			return nil, err
		}
		if j.Status != v1.JobStatus_JOB_STATUS_QUEUED && j.Status != v1.JobStatus_JOB_STATUS_RUNNING {
			return j, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return s.get(ctx, id)
		case <-tick.C:
		}
	}
}

var _ Client = (*Service)(nil)

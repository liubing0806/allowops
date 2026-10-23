package job

import (
	"context"
	"encoding/json"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
)

// A21: job ownership, metadata access, cancellation and output access share this policy.
func (s *Service) authorize(ctx context.Context, j *v1.Job, op authz.Operation, cancel bool, selectedHost string) (uint64, []string, error) {
	if state := operationInfo(ctx); state != nil {
		state.JobID = j.JobId
		state.Version = j.PolicyVersion
	}
	id, ok := reqctx.FromContext(ctx)
	if !ok {
		return 0, nil, failure(connect.CodeUnauthenticated, "AUTHENTICATION_REQUIRED")
	}
	actor, _ := reqctx.RequestInfo(ctx)
	if id.Subject.Kind == "service_account" && j.SubjectId != actor {
		return 0, nil, failure(connect.CodePermissionDenied, "JOB_OWNER_REQUIRED")
	}
	if id.Subject.Kind == "service_account" && (cancel || op == authz.ViewJobs) {
		return j.PolicyVersion, nil, nil
	}
	var raw []byte
	if err := s.Store.Pool.QueryRow(ctx, "SELECT action_definition FROM jobs WHERE job_id=$1", j.JobId).Scan(&raw); err != nil {
		return 0, nil, err
	}
	var action catalog.Action
	if err := json.Unmarshal(raw, &action); err != nil {
		return 0, nil, err
	}
	rows, err := s.Store.Pool.Query(ctx, "SELECT DISTINCT t.host_id,h.authorization_labels FROM tasks t JOIN hosts h ON h.host_id=t.host_id WHERE t.job_id=$1 AND ($2='' OR t.hostname=$2) ORDER BY t.host_id", j.JobId, selectedHost)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	hosts := []authz.Host{}
	for rows.Next() {
		var h authz.Host
		var raw []byte
		if err := rows.Scan(&h.ID, &raw); err != nil {
			return 0, nil, err
		}
		if err := json.Unmarshal(raw, &h.Labels); err != nil {
			return 0, nil, err
		}
		hosts = append(hosts, h)
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	rows.Close()
	// Denied jobs have no tasks, but still require metadata authorization.
	if len(hosts) == 0 {
		hosts = []authz.Host{{}}
	}
	if cancel {
		op = authz.ExecuteAction
	}
	results, version, err := s.Access.RequireBatch(ctx, op, authz.Action{Name: action.Name, Risk: action.Risk}, hosts)
	if err != nil {
		return version, nil, err
	}
	rules := []string{}
	if state := operationInfo(ctx); state != nil {
		state.Version = version
	}
	for _, r := range results {
		rules = append(rules, r.Result.RuleIDs...)
		if state := operationInfo(ctx); state != nil {
			state.Rules = append(state.Rules, r.Result.RuleIDs...)
		}
		if r.Err != nil || r.Result.Decision != "allow" {
			return version, rules, failure(connect.CodePermissionDenied, "JOB_OPERATION_DENIED")
		}
	}
	return version, rules, nil
}

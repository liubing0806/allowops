package api

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/store/db"
)

// SetMaxApprovalTTL configures the ceiling for new policy candidates at startup.
func (s *Service) SetMaxApprovalTTL(maximum time.Duration) { s.maxApprovalTTL = maximum }

func (s *Service) candidateRules(p *v1.PolicyRules) ([]authz.Rule, error) {
	rules, err := rulesFromProto(p)
	if err != nil {
		return nil, err
	}
	for _, rule := range rules {
		if rule.Approval != nil && s.maxApprovalTTL > 0 && time.Duration(rule.Approval.TTLSeconds)*time.Second > s.maxApprovalTTL {
			return nil, failure(connect.CodeInvalidArgument, "approval ttl_seconds exceeds configured maximum")
		}
	}
	return rules, nil
}

func (s *Service) PolicyEngineTx(ctx context.Context, tx pgx.Tx) (*authz.Engine, uint64, error) {
	latest, err := currentPolicyVersion(ctx, tx)
	if err != nil {
		return nil, 0, err
	}
	if current := s.state.Load(); current != nil && current.version == uint64(latest) {
		return current.engine, current.version, nil
	}
	p, err := loadPolicy(ctx, tx, 0)
	if err != nil {
		return nil, 0, err
	}
	rules, err := rulesFromProto(p.Rules)
	if err != nil {
		return nil, 0, err
	}
	engine, err := authz.New(ctx, ruleSource(rules), s.Config.BootstrapAdmins)
	return engine, p.Version, err
}

func (s *Service) EvaluateWithEngine(ctx context.Context, engine *authz.Engine, _ uint64, subject authz.Subject, sourceIP string, op authz.Operation, action authz.Action, hosts []authz.Host) []authz.HostResult {
	results := engine.EvaluateBatch(ctx, authz.Input{Subject: subject, Operation: op, Action: action, Env: authz.Environment{TimeNS: time.Now().UnixNano(), SourceIP: sourceIP}}, hosts)
	if op == authz.ExecuteAction {
		for i, host := range hosts {
			if len(host.Labels) == 0 {
				results[i].Result = authz.Result{Decision: "deny", RuleIDs: []string{"HOST_UNLABELED"}}
			}
		}
	}
	return results
}

func (s *Service) LoadSubjectTx(ctx context.Context, tx pgx.Tx, subjectID, kind string) (authz.Subject, string, string, bool, error) {
	q := db.New(tx)
	if kind == "service_account" {
		a, err := q.GetApprovalServiceAccount(ctx, subjectID)
		if errors.Is(err, pgx.ErrNoRows) {
			return authz.Subject{}, "", "", false, nil
		}
		if err != nil {
			return authz.Subject{}, "", "", false, err
		}
		return authz.Subject{ID: a.AccountID, Kind: kind, Owner: a.OwnerUserID, Roles: a.Roles, Teams: a.Teams}, "", a.OwnerUserID, true, nil
	}
	if err := q.LockApprovalRoleMappings(ctx); err != nil {
		return authz.Subject{}, "", "", false, err
	}
	row, err := q.GetApprovalUser(ctx, subjectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return authz.Subject{}, "", "", false, nil
	}
	if err != nil {
		return authz.Subject{}, "", "", false, err
	}
	u := userFromRow(row)
	if err := mapped(ctx, tx, u.user); err != nil {
		return authz.Subject{}, "", "", false, err
	}
	if (u.kind != "oidc" && u.kind != "ldap") || (kind != "" && u.kind != kind) {
		return authz.Subject{}, "", "", false, nil
	}
	return subject(u), u.user.Email, "", true, nil
}

func (s *Service) LoadUserEmailTx(ctx context.Context, tx pgx.Tx, userID string) (string, error) {
	email, err := db.New(tx).GetConsoleUserEmail(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return email, err
}

func (s *Service) CheckCredentialValidTx(ctx context.Context, tx pgx.Tx, kind, credentialID string) (bool, error) {
	q := db.New(tx)
	switch kind {
	case "service_account":
		return q.IsApprovalTokenValid(ctx, credentialID)
	case "oidc", "ldap":
		return q.IsApprovalSessionValid(ctx, credentialID)
	default:
		return false, nil
	}
}

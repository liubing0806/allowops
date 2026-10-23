package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"google.golang.org/protobuf/encoding/protojson"
)

type ruleSource []authz.Rule

func (r ruleSource) LoadRules(context.Context) ([]authz.Rule, error) { return r, nil }
func rulesFromProto(p *v1.PolicyRules) ([]authz.Rule, error) {
	if p == nil {
		return nil, failure(connect.CodeInvalidArgument, "rules required")
	}
	rules := make([]authz.Rule, 0, len(p.Rules))
	for _, r := range p.Rules {
		rule := authz.Rule{ID: r.Name, Roles: r.Roles, Teams: r.Teams, Owners: r.Owners, Actions: r.Actions, Risks: r.Risks, HostLabels: r.HostLabels, SourceCIDRs: r.SourceCidrs}
		switch r.Effect {
		case v1.PolicyEffect_POLICY_EFFECT_ALLOW:
			rule.Effect = "allow"
		case v1.PolicyEffect_POLICY_EFFECT_DENY:
			rule.Effect = "deny"
		default:
			return nil, failure(connect.CodeInvalidArgument, "rule effect required")
		}
		for _, op := range r.Operations {
			rule.Operations = append(rule.Operations, authz.Operation(op))
		}
		if r.Hours != nil {
			if r.Hours.Timezone == "" || r.Hours.From >= r.Hours.To || r.Hours.To > 24 {
				return nil, failure(connect.CodeInvalidArgument, "valid hours and timezone required")
			}
			rule.Hours = &authz.Hours{From: int(r.Hours.From), To: int(r.Hours.To), Timezone: r.Hours.Timezone}
		}
		rules = append(rules, rule)
	}
	return rules, nil
}
func defaultRules() *v1.PolicyRules {
	p := &v1.PolicyRules{}
	for _, r := range authz.DefaultRules() {
		pr := &v1.PolicyRule{Name: r.ID, Roles: r.Roles, Actions: r.Actions, Risks: r.Risks, Effect: v1.PolicyEffect_POLICY_EFFECT_ALLOW}
		for _, op := range r.Operations {
			pr.Operations = append(pr.Operations, string(op))
		}
		p.Rules = append(p.Rules, pr)
	}
	return p
}
func (s *Service) initialize(ctx context.Context) error {
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(418005)"); err != nil {
		return err
	}
	b, err := encode(defaultRules())
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO policy_versions(version,rules,created_by,reason) VALUES (1,$1,'system','initial defaults') ON CONFLICT DO NOTHING", b); err != nil {
		return err
	}
	var initialized bool
	if err := tx.QueryRow(ctx, "SELECT initialized FROM role_mapping_state FOR UPDATE").Scan(&initialized); err != nil {
		return err
	}
	if !initialized {
		for _, m := range s.Config.RoleMappings {
			if m.ProviderID == "" || m.Group == "" || len(m.Roles) == 0 {
				return failure(connect.CodeInvalidArgument, "initial provider, group and roles required")
			}
			if _, err := tx.Exec(ctx, "INSERT INTO role_mappings(provider_id,group_name,roles) VALUES ($1,$2,$3)", m.ProviderID, m.Group, nonNil(m.Roles)); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, "UPDATE role_mapping_state SET initialized=true"); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
func loadPolicy(ctx context.Context, q querier, version uint64) (*v1.PolicyVersion, error) {
	p := &v1.PolicyVersion{}
	var rules []byte
	var n int64
	var created time.Time
	var from pgtype.Int8
	err := q.QueryRow(ctx, "SELECT version,rules,created_at,created_by,reason,rolled_back_from FROM policy_versions WHERE version=COALESCE(NULLIF($1,0),(SELECT max(version) FROM policy_versions))", version).Scan(&n, &rules, &created, &p.CreatedBy, &p.Reason, &from)
	if err != nil {
		return nil, err
	}
	p.Version, p.CreatedAt, p.Rules = uint64(n), stamp(created), &v1.PolicyRules{}
	if from.Valid {
		value := uint64(from.Int64)
		p.RolledBackFrom = &value
	}
	return p, decode(rules, p.Rules)
}

// refresh brings the loaded policy up to the stored current version. Each call
// reads that version, because every authorization must see the latest policy,
// but the rules are loaded and decoded only when it differs from the loaded one.
func (s *Service) refresh(ctx context.Context) error {
	var latest int64
	if err := s.Store.Pool.QueryRow(ctx, "SELECT COALESCE(max(version),0) FROM policy_versions").Scan(&latest); err != nil {
		return err
	}
	if current := s.state.Load(); current != nil && current.version == uint64(latest) {
		return nil
	}
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	p, err := loadPolicy(ctx, s.Store.Pool, 0)
	if err != nil {
		return err
	}
	current := s.state.Load()
	if current != nil && current.version == p.Version {
		return nil
	}
	rules, err := rulesFromProto(p.Rules)
	if err != nil {
		return err
	}
	engine, err := authz.New(ctx, ruleSource(rules), s.Config.BootstrapAdmins)
	if err != nil {
		return err
	}
	s.state.Store(&policyState{engine: engine, version: p.Version})
	return nil
}

// Start subscribes before the initial reload. Dedicated LISTEN connections do
// not occupy a pooled query connection. Reconnection always reloads missed changes.
func (s *Service) Start(ctx context.Context) error {
	run, cancel := context.WithCancel(ctx)
	conn, err := pgx.ConnectConfig(run, s.Store.Pool.Config().ConnConfig.Copy())
	if err != nil {
		cancel()
		return err
	}
	if _, err := conn.Exec(run, "LISTEN "+PolicyChannel); err != nil {
		conn.Close(run)
		cancel()
		return err
	}
	if err := s.refresh(run); err != nil {
		conn.Close(run)
		cancel()
		return err
	}
	s.cancel = cancel
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			if conn != nil {
				closeCtx, done := context.WithTimeout(context.Background(), time.Second)
				defer done()
				conn.Close(closeCtx)
			}
		}()
		for run.Err() == nil {
			if conn == nil {
				var err error
				conn, err = pgx.ConnectConfig(run, s.Store.Pool.Config().ConnConfig.Copy())
				if err == nil {
					_, err = conn.Exec(run, "LISTEN "+PolicyChannel)
				}
				if err != nil {
					if conn != nil {
						conn.Close(run)
						conn = nil
					}
					select {
					case <-run.Done():
						return
					case <-time.After(time.Second):
					}
					continue
				}
				if err = s.refresh(run); err != nil {
					conn.Close(run)
					conn = nil
					continue
				}
			}
			wait, cancel := context.WithTimeout(run, 30*time.Second)
			_, err := conn.WaitForNotification(wait)
			cancel()
			if err != nil && !errors.Is(err, context.DeadlineExceeded) {
				conn.Close(run)
				conn = nil
				continue
			}
			_ = s.refresh(run) // Require also reloads before every authorization.
		}
	}()
	return nil
}
func (s *Service) Close() {
	if s.cancel != nil {
		s.cancel()
		s.wg.Wait()
	}
}

type policySubject struct {
	ID         string
	Attributes authz.Subject
}
type policySnapshot struct {
	Subjects        []policySubject
	Hosts           []authz.Host
	Actions         []authz.Action
	Bootstrap       []string
	MappingRevision int64
	Revisions       []string
	HostIDs         []string
	CatalogDigests  []string
	ReportedLabels  map[string]map[string]string
}

func (s *Service) snapshot(ctx context.Context, q querier) (*policySnapshot, error) {
	snap := &policySnapshot{Subjects: []policySubject{}, Hosts: []authz.Host{}, Actions: []authz.Action{}, Bootstrap: s.Config.BootstrapAdmins, ReportedLabels: map[string]map[string]string{}}
	users, err := allUsers(ctx, q, "")
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		snap.Subjects = append(snap.Subjects, policySubject{u.user.UserId, subject(u)})
		snap.Revisions = append(snap.Revisions, u.user.UserId+":"+u.user.Revision)
	}
	rows, err := q.Query(ctx, "SELECT "+accountColumns+" FROM service_accounts ORDER BY account_id")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		snap.Subjects = append(snap.Subjects, policySubject{a.AccountId, authz.Subject{ID: a.AccountId, Kind: "service_account", Owner: a.OwnerUserId, Roles: a.Roles, Teams: a.Teams}})
		snap.Revisions = append(snap.Revisions, a.AccountId+":"+a.Revision)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err := q.QueryRow(ctx, "SELECT revision FROM role_mapping_state").Scan(&snap.MappingRevision); err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, "SELECT host_id,hostname,authorization_labels,reported_labels FROM hosts WHERE certificate_status='active' ORDER BY hostname")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		h := authz.Host{}
		var b []byte
		var reported []byte
		var id string
		if err := rows.Scan(&id, &h.ID, &b, &reported); err != nil {
			rows.Close()
			return nil, err
		}
		if err := json.Unmarshal(b, &h.Labels); err != nil {
			rows.Close()
			return nil, err
		}
		var labels map[string]string
		if err := json.Unmarshal(reported, &labels); err != nil {
			rows.Close()
			return nil, err
		}
		snap.ReportedLabels[h.ID] = labels
		snap.Hosts = append(snap.Hosts, h)
		snap.HostIDs = append(snap.HostIDs, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, "SELECT dsse FROM (SELECT DISTINCT ON(catalog_id) catalog_id,dsse,expires_at FROM catalog_versions ORDER BY catalog_id,version DESC) current WHERE expires_at>now() ORDER BY catalog_id")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		snap.CatalogDigests = append(snap.CatalogDigests, base64.RawURLEncoding.EncodeToString(hash(string(raw))))
		e, err := catalog.ParseEnvelope(raw)
		if err != nil {
			rows.Close()
			return nil, err
		}
		b, err := base64.StdEncoding.DecodeString(e.Payload)
		if err != nil {
			rows.Close()
			return nil, err
		}
		var p struct {
			Actions map[string]catalog.Action `json:"actions"`
		}
		if err := json.Unmarshal(b, &p); err != nil {
			rows.Close()
			return nil, err
		}
		names := []string{}
		for name := range p.Actions {
			names = append(names, name)
		}
		for _, name := range unique(names) {
			a := p.Actions[name]
			snap.Actions = append(snap.Actions, authz.Action{Name: name, Risk: a.Risk})
		}
	}
	err = rows.Err()
	rows.Close()
	return snap, err
}

var actionViewOperations = []authz.Operation{authz.ViewCatalog, authz.ViewJobs, authz.ViewOutput}

var consoleOperations = []authz.Operation{authz.ModifyPolicy, authz.ManageServiceAccounts, authz.ManageHosts, authz.CreateJoinToken, authz.ManageUserRoles, authz.PublishCatalog, authz.ViewHosts, authz.ViewCatalog, authz.ViewJobs, authz.ViewOutput, authz.ViewAudit, authz.ViewSystem}

type testEnvironment struct {
	authz.Environment
	Cases []*v1.PolicyTestCase `json:"cases,omitempty"`
}

func (s *Service) inputs(snap *policySnapshot, cases []*v1.PolicyTestCase, env authz.Environment) ([]authz.Input, []uint32, error) {
	inputs := []authz.Input{}
	indices := []uint32{}
	add := func(i authz.Input, index uint32) error {
		if len(inputs) >= s.Config.MaxTestEvaluations {
			return failure(connect.CodeResourceExhausted, "policy evaluation limit exceeded")
		}
		inputs = append(inputs, i)
		indices = append(indices, index)
		return nil
	}
	if len(cases) == 0 {
		// A job without tasks is authorised with (action, empty host).
		jobHosts := append([]authz.Host{{}}, snap.Hosts...)
		for _, sub := range snap.Subjects {
			for _, op := range consoleOperations {
				if err := add(authz.Input{Subject: sub.Attributes, Operation: op, Env: env}, uint32(len(inputs))); err != nil {
					return nil, nil, err
				}
				// Host listing and import preview also have an empty-target check.
				// Retain it above, and cover the stored host attributes used by
				// ListHosts, SetHostLabels and DeleteHost as well.
				if op == authz.ViewHosts || op == authz.ManageHosts {
					for _, h := range snap.Hosts {
						if err := add(authz.Input{Subject: sub.Attributes, Operation: op, Host: h, Env: env}, uint32(len(inputs))); err != nil {
							return nil, nil, err
						}
					}
				}
				if op == authz.ViewCatalog || op == authz.ViewJobs || op == authz.ViewOutput {
					for _, a := range snap.Actions {
						input := authz.Input{Subject: sub.Attributes, Operation: op, Action: a, Env: env}
						if op == authz.ViewCatalog {
							if err := add(input, uint32(len(inputs))); err != nil {
								return nil, nil, err
							}
							continue
						}
						for _, h := range jobHosts {
							input.Host = h
							if err := add(input, uint32(len(inputs))); err != nil {
								return nil, nil, err
							}
						}
					}
				}
			}
			for _, a := range snap.Actions {
				for _, h := range snap.Hosts {
					if err := add(authz.Input{Subject: sub.Attributes, Operation: authz.ExecuteAction, Action: a, Host: h, Env: env}, uint32(len(inputs))); err != nil {
						return nil, nil, err
					}
				}
			}
		}
		return inputs, indices, nil
	}
	for index, c := range cases {
		var sub *policySubject
		for i := range snap.Subjects {
			if snap.Subjects[i].ID == c.SubjectId {
				sub = &snap.Subjects[i]
				break
			}
		}
		if sub == nil {
			return nil, nil, failure(connect.CodeInvalidArgument, "test subject not found")
		}
		e := env
		if c.At != nil {
			if err := c.At.CheckValid(); err != nil {
				return nil, nil, failure(connect.CodeInvalidArgument, "invalid test time")
			}
			e.TimeNS = c.At.AsTime().UnixNano()
		}
		if c.SourceIp != "" {
			e.SourceIP = c.SourceIp
		}
		input := authz.Input{Subject: sub.Attributes, Operation: authz.Operation(c.Operation), Env: e}
		if input.Operation != authz.ExecuteAction && !slices.Contains(consoleOperations, input.Operation) {
			return nil, nil, failure(connect.CodeInvalidArgument, "unknown test operation")
		}
		if _, err := netip.ParseAddr(e.SourceIP); err != nil {
			return nil, nil, failure(connect.CodeInvalidArgument, "invalid test source IP")
		}
		// View operations use the case action when given; without one they stay
		// a global check. execute_action always requires an action.
		if input.Operation == authz.ExecuteAction || (c.Action != "" && slices.Contains(actionViewOperations, input.Operation)) {
			found := false
			for _, a := range snap.Actions {
				if a.Name == c.Action {
					input.Action = a
					found = true
					break
				}
			}
			if !found {
				return nil, nil, failure(connect.CodeInvalidArgument, "test action not found")
			}
		}
		hosts, err := selectHosts(snap.Hosts, c.Targets, snap.ReportedLabels)
		if err != nil {
			return nil, nil, err
		}
		if c.Targets == nil && input.Operation != authz.ExecuteAction {
			hosts = []authz.Host{{}}
		}
		if input.Operation == authz.ExecuteAction && c.Targets == nil {
			return nil, nil, failure(connect.CodeInvalidArgument, "execution test targets required")
		}
		for _, h := range hosts {
			input.Host = h
			if err := add(input, uint32(index)); err != nil {
				return nil, nil, err
			}
		}
	}
	return inputs, indices, nil
}
func selectHosts(hosts []authz.Host, t *v1.HostTargets, reported ...map[string]map[string]string) ([]authz.Host, error) {
	if t == nil {
		return nil, nil
	}
	out := []authz.Host{}
	switch sel := t.Selection.(type) {
	case *v1.HostTargets_Hosts:
		if sel.Hosts == nil || len(sel.Hosts.Names) == 0 {
			return nil, failure(connect.CodeInvalidArgument, "host names required")
		}
		for _, name := range unique(sel.Hosts.Names) {
			found := false
			for _, h := range hosts {
				if h.ID == name {
					out = append(out, h)
					found = true
					break
				}
			}
			if !found {
				return nil, failure(connect.CodeInvalidArgument, "test host not found")
			}
		}
	case *v1.HostTargets_Selector:
		labels := map[string]string{}
		for _, term := range strings.Split(sel.Selector, ",") {
			p := strings.Split(term, "=")
			if len(p) != 2 || strings.TrimSpace(p[0]) == "" || strings.TrimSpace(p[1]) == "" {
				return nil, failure(connect.CodeInvalidArgument, "invalid host selector")
			}
			key, value := strings.TrimSpace(p[0]), strings.TrimSpace(p[1])
			if old, exists := labels[key]; exists && old != value {
				return nil, failure(connect.CodeInvalidArgument, "conflicting host selector conditions")
			}
			labels[key] = value
		}
		for _, h := range hosts {
			match := true
			for k, v := range labels {
				actual := h.Labels[k]
				if strings.HasPrefix(k, "reported.") {
					actual = ""
					if len(reported) > 0 {
						actual = reported[0][h.ID][strings.TrimPrefix(k, "reported.")]
					}
				}
				if actual != v {
					match = false
					break
				}
			}
			if match {
				out = append(out, h)
			}
		}
	default:
		return nil, failure(connect.CodeInvalidArgument, "test targets required")
	}
	return out, nil
}
func actorID(ctx context.Context) string {
	id, _ := FromContext(ctx)
	if id == nil {
		return ""
	}
	if id.User != nil {
		return id.User.UserId
	}
	return id.Subject.ID
}
func decision(r authz.Result, reason string) *v1.PolicyDecision {
	effect := v1.PolicyEffect_POLICY_EFFECT_DENY
	if r.Decision == "allow" {
		effect = v1.PolicyEffect_POLICY_EFFECT_ALLOW
	}
	return &v1.PolicyDecision{Effect: effect, MatchedRules: r.RuleIDs, ErrorReason: reason}
}
func (s *Service) GetPolicy(ctx context.Context, r *connect.Request[v1.GetPolicyRequest]) (*connect.Response[v1.GetPolicyResponse], error) {
	p, err := loadPolicy(ctx, s.Store.Pool, r.Msg.GetVersion())
	return connect.NewResponse(&v1.GetPolicyResponse{Policy: p}), dbError(err)
}
func (s *Service) TestPolicy(ctx context.Context, r *connect.Request[v1.TestPolicyRequest]) (*connect.Response[v1.TestPolicyResponse], error) {
	tx, err := s.Store.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, dbError(err)
	}
	defer tx.Rollback(ctx)
	current, err := loadPolicy(ctx, tx, 0)
	if err != nil {
		return nil, dbError(err)
	}
	if current.Version != r.Msg.BaseVersion {
		return nil, failure(connect.CodeAborted, "policy base version changed")
	}
	var candidate *v1.PolicyRules
	switch c := r.Msg.Candidate.(type) {
	case *v1.TestPolicyRequest_Rules:
		candidate = c.Rules
	case *v1.TestPolicyRequest_HistoricalVersion:
		p, err := loadPolicy(ctx, tx, c.HistoricalVersion)
		if err != nil {
			return nil, dbError(err)
		}
		candidate = p.Rules
	default:
		return nil, failure(connect.CodeInvalidArgument, "candidate required")
	}
	after, err := rulesFromProto(candidate)
	if err != nil {
		return nil, err
	}
	engine, err := authz.New(ctx, ruleSource(after), s.Config.BootstrapAdmins)
	if err != nil {
		return nil, failure(connect.CodeInvalidArgument, "invalid policy rules")
	}
	before, _ := rulesFromProto(current.Rules)
	old, err := authz.New(ctx, ruleSource(before), s.Config.BootstrapAdmins)
	if err != nil {
		return nil, failure(connect.CodeUnavailable, "current policy unavailable")
	}
	snap, err := s.snapshot(ctx, tx)
	if err != nil {
		return nil, dbError(err)
	}
	env := authz.Environment{TimeNS: time.Now().UnixNano(), SourceIP: transport(ctx).ip}
	inputs, indices, err := s.inputs(snap, r.Msg.Cases, env)
	if err != nil {
		return nil, err
	}
	changes := []*v1.PolicyChange{}
	var changed uint64
	for i, input := range inputs {
		b, beforeReason, err := evaluate(ctx, old, input)
		if err != nil {
			return nil, failure(connect.CodeInvalidArgument, "policy evaluation failed")
		}
		a, afterReason, err := evaluate(ctx, engine, input)
		if err != nil {
			return nil, failure(connect.CodeInvalidArgument, "policy evaluation failed")
		}
		different := !reflect.DeepEqual(a, b) || beforeReason != afterReason
		if different {
			changed++
		}
		// Unlabeled hosts need an explicit denial diagnostic even when both
		// versions deny. They do not inflate the actual change count.
		if different || beforeReason != "" || afterReason != "" {
			changes = append(changes, &v1.PolicyChange{CaseIndex: indices[i], Host: input.Host.ID, Before: decision(b, beforeReason), After: decision(a, afterReason)})
		}
	}
	subjects := []authz.Subject{}
	for _, sub := range snap.Subjects {
		subjects = append(subjects, sub.Attributes)
	}
	retains := authz.CheckPolicyUpdate(ctx, after, subjects, env, s.Config.BootstrapAdmins) == nil
	b, _ := encode(candidate)
	sh, err := snapshotHash(snap)
	if err != nil {
		return nil, err
	}
	test := &v1.PolicyTest{TestId: secret("pt_"), BaseVersion: current.Version, CandidateSha256: hash(string(b)), EvaluatedCount: uint64(len(inputs)), ChangedCount: changed, RetainsPolicyAdministrator: retains, ExpiresAt: stamp(time.Now().Add(s.Config.TestTTL))}
	tb, _ := encode(test)
	cb, _ := json.Marshal(changes)
	eb, _ := json.Marshal(testEnvironment{Environment: env, Cases: r.Msg.Cases})
	_, err = tx.Exec(ctx, "INSERT INTO policy_tests(test_id,actor_id,base_version,candidate,candidate_hash,snapshot_hash,environment,test,changes,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", test.TestId, actorID(ctx), current.Version, b, test.CandidateSha256, sh, eb, tb, cb, test.ExpiresAt.AsTime())
	if err != nil {
		return nil, dbError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&v1.TestPolicyResponse{Test: test}), nil
}
func (s *Service) GetPolicyTestChanges(ctx context.Context, r *connect.Request[v1.GetPolicyTestChangesRequest]) (*connect.Response[v1.GetPolicyTestChangesResponse], error) {
	var b []byte
	if err := s.Store.Pool.QueryRow(ctx, "SELECT changes FROM policy_tests WHERE test_id=$1 AND actor_id=$2 AND expires_at>now()", r.Msg.TestId, actorID(ctx)).Scan(&b); err != nil {
		return nil, dbError(err)
	}
	var changes []*v1.PolicyChange
	if err := json.Unmarshal(b, &changes); err != nil {
		return nil, dbError(err)
	}
	changes, p, err := page(ctx, s.Config, "changes:"+r.Msg.TestId+":"+actorID(ctx), r.Msg.Page, changes)
	return connect.NewResponse(&v1.GetPolicyTestChangesResponse{Changes: changes, Page: p}), err
}
func (s *Service) persistPolicy(ctx context.Context, base uint64, candidate *v1.PolicyRules, target uint64, testID, reason string) (*v1.PolicyVersion, error) {
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return nil, dbError(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(418005)"); err != nil {
		return nil, dbError(err)
	}
	// Keep the checked attributes stable through commit without changing P4 writes.
	if _, err := tx.Exec(ctx, "LOCK TABLE console_users,service_accounts,role_mapping_state,role_mappings,hosts,catalog_versions IN SHARE MODE"); err != nil {
		return nil, dbError(err)
	}
	current, err := loadPolicy(ctx, tx, 0)
	if err != nil {
		return nil, dbError(err)
	}
	if current.Version != base {
		return nil, failure(connect.CodeAborted, "policy base version changed")
	}
	if target > 0 {
		p, err := loadPolicy(ctx, tx, target)
		if err != nil {
			return nil, dbError(err)
		}
		candidate = p.Rules
	}
	rules, err := rulesFromProto(candidate)
	if err != nil {
		return nil, err
	}
	nextEngine, err := authz.New(ctx, ruleSource(rules), s.Config.BootstrapAdmins)
	if err != nil {
		return nil, failure(connect.CodeInvalidArgument, "invalid policy rules")
	}
	var candidateHash, storedSnapshot, environment []byte
	if err := tx.QueryRow(ctx, "SELECT candidate_hash,snapshot_hash,environment FROM policy_tests WHERE test_id=$1 AND actor_id=$2 AND base_version=$3 AND expires_at>clock_timestamp() AND NOT consumed FOR UPDATE", testID, actorID(ctx), base).Scan(&candidateHash, &storedSnapshot, &environment); err != nil {
		if err == pgx.ErrNoRows {
			return nil, failure(connect.CodeAborted, "policy test expired or changed")
		}
		return nil, dbError(err)
	}
	b, _ := encode(candidate)
	if !bytes.Equal(candidateHash, hash(string(b))) {
		return nil, failure(connect.CodeAborted, "policy candidate changed")
	}
	snap, err := s.snapshot(ctx, tx)
	if err != nil {
		return nil, dbError(err)
	}
	sh, err := snapshotHash(snap)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(sh, storedSnapshot) {
		return nil, failure(connect.CodeAborted, "policy snapshot changed; test again")
	}
	env := authz.Environment{TimeNS: time.Now().UnixNano(), SourceIP: transport(ctx).ip}
	var previous testEnvironment
	if err := json.Unmarshal(environment, &previous); err != nil {
		return nil, dbError(err)
	}
	if previous.SourceIP != env.SourceIP {
		return nil, failure(connect.CodeAborted, "policy environment changed")
	}
	oldInputs, _, err := s.inputs(snap, previous.Cases, previous.Environment)
	if err != nil {
		return nil, err
	}
	newInputs, _, err := s.inputs(snap, previous.Cases, env)
	if err != nil {
		return nil, err
	}
	oldRules, err := rulesFromProto(current.Rules)
	if err != nil {
		return nil, err
	}
	oldEngine, err := authz.New(ctx, ruleSource(oldRules), s.Config.BootstrapAdmins)
	if err != nil {
		return nil, failure(connect.CodeUnavailable, "current policy unavailable")
	}
	for i, input := range oldInputs {
		for _, engine := range []*authz.Engine{oldEngine, nextEngine} {
			before, beforeReason, err := evaluate(ctx, engine, input)
			if err != nil {
				return nil, failure(connect.CodeAborted, "policy environment changed")
			}
			after, afterReason, err := evaluate(ctx, engine, newInputs[i])
			if err != nil || !reflect.DeepEqual(before, after) || beforeReason != afterReason {
				return nil, failure(connect.CodeAborted, "policy environment changed; test again")
			}
		}
	}
	subjects := []authz.Subject{}
	for _, sub := range snap.Subjects {
		subjects = append(subjects, sub.Attributes)
	}
	if err := authz.CheckPolicyUpdate(ctx, rules, subjects, env, s.Config.BootstrapAdmins); err != nil {
		return nil, failure(connect.CodeFailedPrecondition, "policy would lock out administrators")
	}
	var rolled any
	if target > 0 {
		rolled = target
	}
	if _, err := tx.Exec(ctx, "INSERT INTO policy_versions(version,rules,created_by,reason,rolled_back_from) VALUES ($1,$2,$3,$4,$5)", base+1, b, actorID(ctx), reason, rolled); err != nil {
		return nil, dbError(err)
	}
	if _, err := tx.Exec(ctx, "UPDATE policy_tests SET consumed=true WHERE test_id=$1", testID); err != nil {
		return nil, dbError(err)
	}
	if _, err := tx.Exec(ctx, "SELECT pg_notify($1,$2)", PolicyChannel, strconv.FormatUint(base+1, 10)); err != nil {
		return nil, dbError(err)
	}
	p, err := loadPolicy(ctx, tx, base+1)
	if err != nil {
		return nil, dbError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, dbError(err)
	}
	recordAuditTarget(ctx, "policy_version", strconv.FormatUint(p.Version, 10))
	if err := s.refresh(ctx); err != nil {
		return nil, failure(connect.CodeUnavailable, "saved policy reload failed")
	}
	return p, nil
}
func (s *Service) SavePolicy(ctx context.Context, r *connect.Request[v1.SavePolicyRequest]) (*connect.Response[v1.SavePolicyResponse], error) {
	p, err := s.persistPolicy(ctx, r.Msg.BaseVersion, r.Msg.Rules, 0, r.Msg.TestId, r.Msg.Reason)
	return connect.NewResponse(&v1.SavePolicyResponse{Policy: p}), err
}
func (s *Service) RollbackPolicy(ctx context.Context, r *connect.Request[v1.RollbackPolicyRequest]) (*connect.Response[v1.RollbackPolicyResponse], error) {
	if r.Msg.TargetVersion == 0 {
		return nil, failure(connect.CodeInvalidArgument, "target version required")
	}
	p, err := s.persistPolicy(ctx, r.Msg.BaseVersion, nil, r.Msg.TargetVersion, r.Msg.TestId, r.Msg.Reason)
	return connect.NewResponse(&v1.RollbackPolicyResponse{Policy: p}), err
}
func (s *Service) ListPolicyHistory(ctx context.Context, r *connect.Request[v1.ListPolicyHistoryRequest]) (*connect.Response[v1.ListPolicyHistoryResponse], error) {
	rows, err := s.Store.Pool.Query(ctx, "SELECT version FROM policy_versions ORDER BY version DESC")
	if err != nil {
		return nil, dbError(err)
	}
	versions := []uint64{}
	for rows.Next() {
		var n uint64
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, dbError(err)
		}
		versions = append(versions, n)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, dbError(err)
	}
	total := len(versions)
	versions, _, err = page(ctx, s.Config, "policy_history", r.Msg.Page, versions)
	if err != nil {
		return nil, err
	}
	items := []*v1.PolicyVersion{}
	for _, n := range versions {
		v, err := loadPolicy(ctx, s.Store.Pool, n)
		if err != nil {
			return nil, dbError(err)
		}
		items = append(items, v)
	}
	offset := 0
	if token := r.Msg.GetPage().GetPageToken(); token != "" {
		b, _ := base64.RawURLEncoding.DecodeString(token)
		parts := strings.Split(string(b), ":")
		offset, _ = strconv.Atoi(parts[1])
	} // Validated by page above.
	end := 0
	p := &v1.PageResponse{}
	for candidate := 1; candidate <= len(items); candidate++ {
		next := &v1.PageResponse{}
		if offset+candidate < total {
			binding := base64.RawURLEncoding.EncodeToString(hash("policy_history:" + actorID(ctx)))
			next.NextPageToken = base64.RawURLEncoding.EncodeToString([]byte(binding + ":" + strconv.Itoa(offset+candidate)))
		}
		b, err := protojson.Marshal(&v1.ListPolicyHistoryResponse{Policies: items[:candidate], Page: next})
		if err != nil {
			return nil, failure(connect.CodeInternal, "list encoding failed")
		}
		if len(b) <= s.Config.MessageBytes {
			end = candidate
			p = next
		}
	}
	if len(items) > 0 && end == 0 {
		return nil, failure(connect.CodeResourceExhausted, "list item exceeds message limit")
	}
	items = items[:end]
	return connect.NewResponse(&v1.ListPolicyHistoryResponse{Policies: items, Page: p}), nil
}

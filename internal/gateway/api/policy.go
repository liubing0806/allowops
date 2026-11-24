package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
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
	if err := lockPolicyWrites(ctx, tx); err != nil {
		return err
	}
	b, err := encode(defaultRules())
	if err != nil {
		return err
	}
	if err := insertInitialPolicy(ctx, tx, b); err != nil {
		return err
	}
	initialized, err := lockMappingState(ctx, tx)
	if err != nil {
		return err
	}
	if !initialized {
		for _, m := range s.Config.RoleMappings {
			if m.ProviderID == "" || m.Group == "" || len(m.Roles) == 0 {
				return failure(connect.CodeInvalidArgument, "initial provider, group and roles required")
			}
			if err := insertRoleMapping(ctx, tx, m.ProviderID, m.Group, nonNil(m.Roles)); err != nil {
				return err
			}
		}
		if err := markMappingsInitialized(ctx, tx); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func loadPolicy(ctx context.Context, q querier, version uint64) (*v1.PolicyVersion, error) {
	row, err := getPolicyVersion(ctx, q, version)
	if err != nil {
		return nil, err
	}
	p := &v1.PolicyVersion{CreatedBy: row.CreatedBy, Reason: row.Reason}
	p.Version, p.CreatedAt, p.Rules = uint64(row.Version), stamp(row.CreatedAt.Time), &v1.PolicyRules{}
	if row.RolledBackFrom.Valid {
		value := uint64(row.RolledBackFrom.Int64)
		p.RolledBackFrom = &value
	}
	return p, decode(row.Rules, p.Rules)
}

// refresh brings the loaded policy up to the stored current version. Each call
// reads that version, because every authorization must see the latest policy,
// but the rules are loaded and decoded only when it differs from the loaded one.
func (s *Service) refresh(ctx context.Context) error {
	latest, err := currentPolicyVersion(ctx, s.Store.Pool)
	if err != nil {
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
	if err := listenPolicy(run, conn); err != nil {
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
	s.wg.Add(2)
	go s.maintainExpiry(run)
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
					err = listenPolicy(run, conn)
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
		if u.user.Disabled {
			continue
		}
		snap.Subjects = append(snap.Subjects, policySubject{u.user.UserId, subject(u)})
		snap.Revisions = append(snap.Revisions, u.user.UserId+":"+u.user.Revision)
	}
	accounts, err := listAccounts(ctx, q)
	if err != nil {
		return nil, err
	}
	for _, a := range accounts {
		snap.Subjects = append(snap.Subjects, policySubject{a.AccountId, authz.Subject{ID: a.AccountId, Kind: "service_account", Owner: a.OwnerUserId, Roles: a.Roles, Teams: a.Teams}})
		snap.Revisions = append(snap.Revisions, a.AccountId+":"+a.Revision)
	}
	if snap.MappingRevision, err = mappingRevision(ctx, q); err != nil {
		return nil, err
	}
	if err = snapshotHosts(ctx, q, snap); err != nil {
		return nil, err
	}
	return snap, snapshotActions(ctx, q, snap)
}

// snapshotHosts adds the active hosts with their authorization and reported labels.
func snapshotHosts(ctx context.Context, q querier, snap *policySnapshot) error {
	rows, err := activeHostLabels(ctx, q)
	if err != nil {
		return err
	}
	for _, r := range rows {
		h := authz.Host{ID: r.Hostname}
		if err := json.Unmarshal(r.AuthorizationLabels, &h.Labels); err != nil {
			return err
		}
		var labels map[string]string
		if err := json.Unmarshal(r.ReportedLabels, &labels); err != nil {
			return err
		}
		snap.ReportedLabels[h.ID] = labels
		snap.Hosts = append(snap.Hosts, h)
		snap.HostIDs = append(snap.HostIDs, r.HostID)
	}
	return nil
}

// snapshotActions adds the digests and actions of the unexpired current catalogs.
func snapshotActions(ctx context.Context, q querier, snap *policySnapshot) error {
	envelopes, err := currentCatalogEnvelopes(ctx, q)
	if err != nil {
		return err
	}
	for _, raw := range envelopes {
		snap.CatalogDigests = append(snap.CatalogDigests, base64.RawURLEncoding.EncodeToString(hash(string(raw))))
		e, err := catalog.ParseEnvelope(raw)
		if err != nil {
			return err
		}
		b, err := base64.StdEncoding.DecodeString(e.Payload)
		if err != nil {
			return err
		}
		var p struct {
			Actions map[string]catalog.Action `json:"actions"`
		}
		if err := json.Unmarshal(b, &p); err != nil {
			return err
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
	return nil
}

var actionViewOperations = []authz.Operation{authz.ViewCatalog, authz.ViewJobs, authz.ViewOutput}

var consoleOperations = []authz.Operation{authz.ModifyPolicy, authz.ManageServiceAccounts, authz.ManageHosts, authz.CreateJoinToken, authz.ManageUserRoles, authz.PublishCatalog, authz.ViewHosts, authz.ViewInventory, authz.ViewChanges, authz.ViewKnowledge, authz.ViewCatalog, authz.ViewJobs, authz.ViewOutput, authz.ViewAudit, authz.ViewSystem}

type testEnvironment struct {
	authz.Environment
	Cases []*v1.PolicyTestCase `json:"cases,omitempty"`
}

// Stored tests use encoding/json, which preserves the oneof wrapper but cannot
// decode it into the generated HostTargets.Selection interface on its own.
func decodeTestEnvironment(data []byte) (testEnvironment, error) {
	var stored struct {
		authz.Environment
		Cases []struct {
			v1.PolicyTestCase
			Targets *struct {
				Selection struct {
					Hosts    *v1.HostNames
					Selector *string
				}
			} `json:"targets"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		return testEnvironment{}, err
	}
	result := testEnvironment{Environment: stored.Environment}
	for i := range stored.Cases {
		c := &stored.Cases[i]
		if c.Targets != nil {
			selection := c.Targets.Selection
			c.PolicyTestCase.Targets = &v1.HostTargets{}
			switch {
			case selection.Hosts != nil:
				c.PolicyTestCase.Targets.Selection = &v1.HostTargets_Hosts{Hosts: selection.Hosts}
			case selection.Selector != nil:
				c.PolicyTestCase.Targets.Selection = &v1.HostTargets_Selector{Selector: *selection.Selector}
			}
		}
		result.Cases = append(result.Cases, &c.PolicyTestCase)
	}
	return result, nil
}

type policyInputHosts struct {
	all             []authz.Host
	groupIndices    []int
	representatives []authz.Host
}

func groupPolicyHosts(hosts []authz.Host) policyInputHosts {
	groups := policyInputHosts{all: hosts, groupIndices: make([]int, len(hosts))}
	seen := map[string]int{}
	for i, host := range hosts {
		key := ""
		// Rego only uses host.labels. The unlabeled execution check also
		// treats nil and empty label maps alike.
		if len(host.Labels) > 0 {
			encoded, _ := json.Marshal(host.Labels) // String maps have sorted keys and cannot fail encoding.
			key = string(encoded)
		}
		group, exists := seen[key]
		if !exists {
			group = len(groups.representatives)
			seen[key] = group
			groups.representatives = append(groups.representatives, host)
		}
		groups.groupIndices[i] = group
	}
	return groups
}

type policyInputBatch struct {
	input     authz.Input
	hosts     policyInputHosts
	firstCase uint32
	explicit  bool
}

func (b policyInputBatch) caseIndex(hostIndex int) uint32 {
	if b.explicit {
		return b.firstCase
	}
	return b.firstCase + uint32(hostIndex)
}

// inputCollector accumulates policy evaluation inputs up to the configured limit.
type inputCollector struct {
	limit       int
	evaluations int
	count       uint64 // Logical inputs, including every host in each group.
	explicit    bool
	batches     []policyInputBatch
}

func (c *inputCollector) add(input authz.Input, hosts policyInputHosts, index uint32) error {
	if len(hosts.all) == 0 {
		return nil
	}
	if len(hosts.representatives) > c.limit-c.evaluations {
		err := connect.NewError(connect.CodeResourceExhausted, fmt.Errorf("policy evaluation limit exceeded after grouping hosts by authorization labels (limit %d). Use a smaller set of explicit test cases or increase identity.max_test_evaluations", c.limit))
		detail, detailErr := connect.NewErrorDetail(&v1.ErrorDetail{Reason: "POLICY_EVALUATION_LIMIT_EXCEEDED"})
		if detailErr == nil {
			err.AddDetail(detail)
		}
		return err
	}
	count := c.count + uint64(len(hosts.all))
	if !c.explicit {
		if count > math.MaxUint32+1 {
			return failure(connect.CodeResourceExhausted, "expanded policy trial exceeds the case index range. Use explicit test cases")
		}
		index = uint32(c.count)
	}
	c.batches = append(c.batches, policyInputBatch{input: input, hosts: hosts, firstCase: index, explicit: c.explicit})
	c.evaluations += len(hosts.representatives)
	c.count = count
	return nil
}

func (s *Service) collectPolicyInputs(snap *policySnapshot, cases []*v1.PolicyTestCase, env authz.Environment) (*inputCollector, error) {
	c := &inputCollector{limit: s.Config.MaxTestEvaluations, explicit: len(cases) > 0}
	var err error
	if c.explicit {
		err = caseInputs(c, snap, cases, env)
	} else {
		err = defaultInputs(c, snap, env)
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// defaultInputs covers every console operation, and execution of every action
// on every host, for every subject.
func defaultInputs(c *inputCollector, snap *policySnapshot, env authz.Environment) error {
	global := groupPolicyHosts([]authz.Host{{}})
	hosts := groupPolicyHosts(snap.Hosts)
	// Host listing and import preview have an empty-target check. A job
	// without tasks is also authorised with (action, empty host).
	hostsAndGlobal := groupPolicyHosts(append([]authz.Host{{}}, snap.Hosts...))
	for _, sub := range snap.Subjects {
		for _, op := range consoleOperations {
			input := authz.Input{Subject: sub.Attributes, Operation: op, Env: env}
			targets := global
			if op == authz.ViewHosts || op == authz.ManageHosts {
				// Cover the stored attributes used by ListHosts, SetHostLabels and DeleteHost.
				targets = hostsAndGlobal
			}
			if err := c.add(input, targets, 0); err != nil {
				return err
			}
			switch op {
			case authz.ViewCatalog, authz.ViewJobs, authz.ViewOutput:
				targets := hostsAndGlobal
				if op == authz.ViewCatalog {
					targets = global
				}
				for _, action := range snap.Actions {
					input.Action = action
					if err := c.add(input, targets, 0); err != nil {
						return err
					}
				}
			}
		}
		for _, action := range snap.Actions {
			if err := c.add(authz.Input{Subject: sub.Attributes, Operation: authz.ExecuteAction, Action: action, Env: env}, hosts, 0); err != nil {
				return err
			}
		}
	}
	return nil
}

func caseInputs(c *inputCollector, snap *policySnapshot, cases []*v1.PolicyTestCase, env authz.Environment) error {
	for index, tc := range cases {
		input, hosts, err := caseInput(snap, tc, env)
		if err != nil {
			return err
		}
		if err := c.add(input, groupPolicyHosts(hosts), uint32(index)); err != nil {
			return err
		}
	}
	return nil
}

// caseInput validates one test case and returns its input without a host
// together with the hosts it targets.
func caseInput(snap *policySnapshot, c *v1.PolicyTestCase, env authz.Environment) (authz.Input, []authz.Host, error) {
	var sub *policySubject
	for i := range snap.Subjects {
		if snap.Subjects[i].ID == c.SubjectId {
			sub = &snap.Subjects[i]
			break
		}
	}
	if sub == nil {
		return authz.Input{}, nil, failure(connect.CodeInvalidArgument, "test subject not found")
	}
	e := env
	if c.At != nil {
		if err := c.At.CheckValid(); err != nil {
			return authz.Input{}, nil, failure(connect.CodeInvalidArgument, "invalid test time")
		}
		e.TimeNS = c.At.AsTime().UnixNano()
	}
	if c.SourceIp != "" {
		e.SourceIP = c.SourceIp
	}
	input := authz.Input{Subject: sub.Attributes, Operation: authz.Operation(c.Operation), Env: e}
	if input.Operation != authz.ExecuteAction && !slices.Contains(consoleOperations, input.Operation) {
		return authz.Input{}, nil, failure(connect.CodeInvalidArgument, "unknown test operation")
	}
	if _, err := netip.ParseAddr(e.SourceIP); err != nil {
		return authz.Input{}, nil, failure(connect.CodeInvalidArgument, "invalid test source IP")
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
			return authz.Input{}, nil, failure(connect.CodeInvalidArgument, "test action not found")
		}
	}
	hosts, err := selectHosts(snap.Hosts, c.Targets, snap.ReportedLabels)
	if err != nil {
		return authz.Input{}, nil, err
	}
	if c.Targets == nil && input.Operation != authz.ExecuteAction {
		hosts = []authz.Host{{}}
	}
	if input.Operation == authz.ExecuteAction && c.Targets == nil {
		return authz.Input{}, nil, failure(connect.CodeInvalidArgument, "execution test targets required")
	}
	return input, hosts, nil
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
	inputs, err := s.collectPolicyInputs(snap, r.Msg.Cases, env)
	if err != nil {
		return nil, err
	}
	changes, changed, err := comparePolicyInputs(ctx, inputs, old, engine)
	if err != nil {
		return nil, err
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
	test := &v1.PolicyTest{TestId: secret("pt_"), BaseVersion: current.Version, CandidateSha256: hash(string(b)), EvaluatedCount: inputs.count, ChangedCount: changed, RetainsPolicyAdministrator: retains, ExpiresAt: stamp(time.Now().Add(s.Config.TestTTL))}
	tb, _ := encode(test)
	cb, _ := json.Marshal(changes)
	eb, _ := json.Marshal(testEnvironment{Environment: env, Cases: r.Msg.Cases})
	err = insertPolicyTest(ctx, tx, policyTest{id: test.TestId, actor: reqctx.ActorID(ctx), baseVersion: current.Version, candidate: b, candidateHash: test.CandidateSha256, snapshotHash: sh, environment: eb, test: tb, changes: cb, expires: test.ExpiresAt.AsTime()})
	if err != nil {
		return nil, dbError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, dbError(err)
	}
	return connect.NewResponse(&v1.TestPolicyResponse{Test: test}), nil
}

func comparePolicyInputs(ctx context.Context, inputs *inputCollector, old, next *authz.Engine) ([]*v1.PolicyChange, uint64, error) {
	type comparedDecision struct {
		before, after *v1.PolicyDecision
		different     bool
	}
	changes := []*v1.PolicyChange{}
	var changed uint64
	for _, batch := range inputs.batches {
		input := batch.input
		decisions := make([]comparedDecision, len(batch.hosts.representatives))
		hasChanges := false
		for group, host := range batch.hosts.representatives {
			input.Host = host
			before, beforeReason, err := evaluate(ctx, old, input)
			if err != nil {
				return nil, 0, failure(connect.CodeInvalidArgument, "policy evaluation failed")
			}
			after, afterReason, err := evaluate(ctx, next, input)
			if err != nil {
				return nil, 0, failure(connect.CodeInvalidArgument, "policy evaluation failed")
			}
			different := !reflect.DeepEqual(before, after) || beforeReason != afterReason
			// Include unlabeled-host diagnostics even if both versions deny.
			if different || beforeReason != "" || afterReason != "" {
				decisions[group] = comparedDecision{decision(before, beforeReason), decision(after, afterReason), different}
				hasChanges = true
			}
		}
		if !hasChanges {
			continue
		}
		for i, host := range batch.hosts.all {
			result := decisions[batch.hosts.groupIndices[i]]
			if result.before == nil {
				continue
			}
			if result.different {
				changed++
			}
			changes = append(changes, &v1.PolicyChange{CaseIndex: batch.caseIndex(i), Host: host.ID, Before: result.before, After: result.after})
		}
	}
	return changes, changed, nil
}

func (s *Service) GetPolicyTestChanges(ctx context.Context, r *connect.Request[v1.GetPolicyTestChangesRequest]) (*connect.Response[v1.GetPolicyTestChangesResponse], error) {
	b, err := policyTestChanges(ctx, s.Store.Pool, r.Msg.TestId, reqctx.ActorID(ctx))
	if err != nil {
		return nil, dbError(err)
	}
	var changes []*v1.PolicyChange
	if err := json.Unmarshal(b, &changes); err != nil {
		return nil, dbError(err)
	}
	changes, p, err := page(ctx, s.Config, "changes:"+r.Msg.TestId+":"+reqctx.ActorID(ctx), r.Msg.Page, changes)
	return connect.NewResponse(&v1.GetPolicyTestChangesResponse{Changes: changes, Page: p}), err
}

func (s *Service) persistPolicy(ctx context.Context, base uint64, candidate *v1.PolicyRules, target uint64, testID, reason string) (*v1.PolicyVersion, error) {
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return nil, dbError(err)
	}
	defer tx.Rollback(ctx)
	if err := lockPolicyWrites(ctx, tx); err != nil {
		return nil, dbError(err)
	}
	// Keep the checked attributes stable through commit without changing the gateway foundation's host-registry writes (design P4).
	if err := lockPolicyInputs(ctx, tx); err != nil {
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
	b, _ := encode(candidate)
	snap, previous, env, err := s.verifyPolicyTest(ctx, tx, testID, base, b)
	if err != nil {
		return nil, err
	}
	if err := s.verifyEnvironment(ctx, snap, previous, env, current, nextEngine); err != nil {
		return nil, err
	}
	subjects := []authz.Subject{}
	for _, sub := range snap.Subjects {
		subjects = append(subjects, sub.Attributes)
	}
	if err := authz.CheckPolicyUpdate(ctx, rules, subjects, env, s.Config.BootstrapAdmins); err != nil {
		return nil, failure(connect.CodeFailedPrecondition, "policy would lock out administrators")
	}
	p, err := writePolicyVersion(ctx, tx, base, b, reason, target, testID)
	if err != nil {
		return nil, err
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

// verifyPolicyTest locks the stored test and checks that the candidate (b, its
// JSON encoding), the database snapshot and the source address still match it.
// It returns the current snapshot, the stored test environment and the
// environment of this request.
func (s *Service) verifyPolicyTest(ctx context.Context, tx pgx.Tx, testID string, base uint64, b []byte) (*policySnapshot, testEnvironment, authz.Environment, error) {
	var previous testEnvironment
	var env authz.Environment
	candidateHash, storedSnapshot, environment, err := lockPolicyTest(ctx, tx, testID, reqctx.ActorID(ctx), base)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, previous, env, failure(connect.CodeAborted, "policy test expired or changed")
		}
		return nil, previous, env, dbError(err)
	}
	if !bytes.Equal(candidateHash, hash(string(b))) {
		return nil, previous, env, failure(connect.CodeAborted, "policy candidate changed")
	}
	snap, err := s.snapshot(ctx, tx)
	if err != nil {
		return nil, previous, env, dbError(err)
	}
	sh, err := snapshotHash(snap)
	if err != nil {
		return nil, previous, env, err
	}
	if !bytes.Equal(sh, storedSnapshot) {
		return nil, previous, env, failure(connect.CodeAborted, "policy snapshot changed; test again")
	}
	env = authz.Environment{TimeNS: time.Now().UnixNano(), SourceIP: transport(ctx).ip}
	previous, err = decodeTestEnvironment(environment)
	if err != nil {
		return nil, previous, env, dbError(err)
	}
	if previous.SourceIP != env.SourceIP {
		return nil, previous, env, failure(connect.CodeAborted, "policy environment changed")
	}
	return snap, previous, env, nil
}

// verifyEnvironment checks that the decisions of the current and the next
// engine do not depend on the time difference between the stored test and now.
func (s *Service) verifyEnvironment(ctx context.Context, snap *policySnapshot, previous testEnvironment, env authz.Environment, current *v1.PolicyVersion, nextEngine *authz.Engine) error {
	oldInputs, err := s.collectPolicyInputs(snap, previous.Cases, previous.Environment)
	if err != nil {
		return err
	}
	newInputs, err := s.collectPolicyInputs(snap, previous.Cases, env)
	if err != nil {
		return err
	}
	oldRules, err := rulesFromProto(current.Rules)
	if err != nil {
		return err
	}
	oldEngine, err := authz.New(ctx, ruleSource(oldRules), s.Config.BootstrapAdmins)
	if err != nil {
		return failure(connect.CodeUnavailable, "current policy unavailable")
	}
	for i, batch := range oldInputs.batches {
		oldInput, newInput := batch.input, newInputs.batches[i].input
		for _, host := range batch.hosts.representatives {
			oldInput.Host, newInput.Host = host, host
			for _, engine := range []*authz.Engine{oldEngine, nextEngine} {
				before, beforeReason, err := evaluate(ctx, engine, oldInput)
				if err != nil {
					return failure(connect.CodeAborted, "policy environment changed")
				}
				after, afterReason, err := evaluate(ctx, engine, newInput)
				if err != nil || !reflect.DeepEqual(before, after) || beforeReason != afterReason {
					return failure(connect.CodeAborted, "policy environment changed; test again")
				}
			}
		}
	}
	return nil
}

// writePolicyVersion stores version base+1 (b is its JSON encoded rules),
// consumes the test, announces the version and reads it back.
func writePolicyVersion(ctx context.Context, tx pgx.Tx, base uint64, b []byte, reason string, target uint64, testID string) (*v1.PolicyVersion, error) {
	var rolled any
	if target > 0 {
		rolled = target
	}
	if err := insertPolicyVersion(ctx, tx, base+1, b, reqctx.ActorID(ctx), reason, rolled); err != nil {
		return nil, dbError(err)
	}
	if err := consumePolicyTest(ctx, tx, testID); err != nil {
		return nil, dbError(err)
	}
	if err := notifyPolicy(ctx, tx, strconv.FormatUint(base+1, 10)); err != nil {
		return nil, dbError(err)
	}
	p, err := loadPolicy(ctx, tx, base+1)
	if err != nil {
		return nil, dbError(err)
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
	versions, err := listPolicyVersions(ctx, s.Store.Pool)
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
			binding := base64.RawURLEncoding.EncodeToString(hash("policy_history:" + reqctx.ActorID(ctx)))
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

package api

import (
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func policyInputsFixture() (*Service, *policySnapshot, authz.Environment) {
	s := &Service{Config: Config{MaxTestEvaluations: 10}}
	snap := &policySnapshot{
		Subjects:       []policySubject{{ID: "inspector", Attributes: authz.Subject{ID: "inspector"}}},
		Actions:        []authz.Action{{Name: "restart", Risk: "dangerous"}},
		Hosts:          []authz.Host{{ID: "dev", Labels: map[string]string{"env": "dev"}}, {ID: "prod", Labels: map[string]string{"env": "prod"}}},
		ReportedLabels: map[string]map[string]string{},
	}
	return s, snap, authz.Environment{TimeNS: 1234567890, SourceIP: "192.0.2.1"}
}

func hostNames(names ...string) *v1.HostTargets {
	return &v1.HostTargets{Selection: &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: names}}}
}

func TestPolicyInputsRejectInvalidCases(t *testing.T) {
	s, snap, env := policyInputsFixture()
	cases := []struct {
		name string
		c    *v1.PolicyTestCase
		code connect.Code
		msg  string
	}{
		{"unknown subject", &v1.PolicyTestCase{SubjectId: "ghost", Operation: string(authz.ViewJobs)}, connect.CodeInvalidArgument, "test subject not found"},
		{"invalid time", &v1.PolicyTestCase{SubjectId: "inspector", Operation: string(authz.ViewJobs), At: &timestamppb.Timestamp{Seconds: 1 << 40}}, connect.CodeInvalidArgument, "invalid test time"},
		{"unknown operation", &v1.PolicyTestCase{SubjectId: "inspector", Operation: "bogus"}, connect.CodeInvalidArgument, "unknown test operation"},
		{"invalid source ip", &v1.PolicyTestCase{SubjectId: "inspector", Operation: string(authz.ViewJobs), SourceIp: "not-an-ip"}, connect.CodeInvalidArgument, "invalid test source IP"},
		{"unknown action", &v1.PolicyTestCase{SubjectId: "inspector", Operation: string(authz.ExecuteAction), Action: "missing", Targets: hostNames("dev")}, connect.CodeInvalidArgument, "test action not found"},
		{"execute without action", &v1.PolicyTestCase{SubjectId: "inspector", Operation: string(authz.ExecuteAction), Targets: hostNames("dev")}, connect.CodeInvalidArgument, "test action not found"},
		{"execute without targets", &v1.PolicyTestCase{SubjectId: "inspector", Operation: string(authz.ExecuteAction), Action: "restart"}, connect.CodeInvalidArgument, "execution test targets required"},
		{"unknown host", &v1.PolicyTestCase{SubjectId: "inspector", Operation: string(authz.ExecuteAction), Action: "restart", Targets: hostNames("ghost")}, connect.CodeInvalidArgument, "test host not found"},
	}
	for _, tc := range cases {
		_, _, err := s.inputs(snap, []*v1.PolicyTestCase{tc.c}, env)
		if err == nil || connect.CodeOf(err) != tc.code || err.(*connect.Error).Message() != tc.msg {
			t.Errorf("%s: got %v, want %v %q", tc.name, err, tc.code, tc.msg)
		}
	}
	s.Config.MaxTestEvaluations = 1
	_, _, err := s.inputs(snap, []*v1.PolicyTestCase{{SubjectId: "inspector", Operation: string(authz.ExecuteAction), Action: "restart", Targets: hostNames("dev", "prod")}}, env)
	if err == nil || connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Errorf("evaluation limit: got %v", err)
	}
}

func TestPolicyInputsExpandCases(t *testing.T) {
	s, snap, env := policyInputsFixture()
	at := timestamppb.New(timestamppb.Now().AsTime())
	inputs, indices, err := s.inputs(snap, []*v1.PolicyTestCase{
		{SubjectId: "inspector", Operation: string(authz.ExecuteAction), Action: "restart", Targets: hostNames("dev", "prod"), At: at, SourceIp: "198.51.100.7"},
		{SubjectId: "inspector", Operation: string(authz.ViewHosts)},
		{SubjectId: "inspector", Operation: string(authz.ViewJobs), Action: "restart", Targets: &v1.HostTargets{Selection: &v1.HostTargets_Selector{Selector: "env=prod"}}},
	}, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 4 {
		t.Fatalf("got %d inputs, want 4", len(inputs))
	}
	wantIndex := []uint32{0, 0, 1, 2}
	wantHost := []string{"dev", "prod", "", "prod"}
	for i, in := range inputs {
		if indices[i] != wantIndex[i] || in.Host.ID != wantHost[i] {
			t.Errorf("input %d: index %d host %q, want %d %q", i, indices[i], in.Host.ID, wantIndex[i], wantHost[i])
		}
	}
	if inputs[0].Env.TimeNS != at.AsTime().UnixNano() || inputs[0].Env.SourceIP != "198.51.100.7" || inputs[2].Env != env {
		t.Errorf("case environment overrides leaked or were lost: %+v %+v", inputs[0].Env, inputs[2].Env)
	}
	if inputs[0].Action.Name != "restart" || inputs[2].Action.Name != "" || inputs[3].Action.Name != "restart" {
		t.Errorf("case actions wrong: %+v", inputs)
	}
}

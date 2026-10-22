package authz

import "context"

type Operation string

const (
	ExecuteAction         Operation = "execute_action"
	ModifyPolicy          Operation = "modify_policy"
	ManageServiceAccounts Operation = "manage_service_accounts"
	ManageHosts           Operation = "manage_hosts"
	CreateJoinToken       Operation = "create_join_token"
	ManageUserRoles       Operation = "manage_user_roles"
	PublishCatalog        Operation = "publish_catalog"
	ViewHosts             Operation = "view_hosts"
	ViewCatalog           Operation = "view_catalog"
	ViewJobs              Operation = "view_jobs"
	ViewOutput            Operation = "view_output"
	ViewAudit             Operation = "view_audit"
	ViewSystem            Operation = "view_system"
)

// Subject must be built from an authenticated identity. OIDC Email must be verified.
// Kind is oidc, ldap, or service_account; ID is the OIDC subject or LDAP username.
type Subject struct {
	ID    string   `json:"id"`
	Kind  string   `json:"kind"`
	Email string   `json:"email"`
	Roles []string `json:"roles"`
	Teams []string `json:"teams"`
	Owner string   `json:"owner"`
}

type Action struct {
	Name string `json:"name"`
	Risk string `json:"risk"`
}

type Host struct {
	ID     string            `json:"id"`
	Labels map[string]string `json:"labels"`
}

type Environment struct {
	TimeNS   int64  `json:"time_ns"`
	SourceIP string `json:"source_ip"`
}

type Input struct {
	Subject   Subject     `json:"subject"`
	Operation Operation   `json:"operation"`
	Action    Action      `json:"action"`
	Host      Host        `json:"host"`
	Env       Environment `json:"env"`
}

// Hours is a half-open interval in an IANA timezone. Empty timezone retains
// Asia/Shanghai for existing P5A callers. Overnight intervals are not supported.
type Hours struct {
	From     int    `json:"from"`
	To       int    `json:"to"`
	Timezone string `json:"timezone,omitempty"`
}

// Rule uses OR within roles/actions/risks and AND between the other conditions.
// Empty optional conditions impose no restriction; Operations and Roles are required.
type Rule struct {
	ID          string            `json:"id"`
	Effect      string            `json:"effect"`
	Roles       []string          `json:"roles"`
	Operations  []Operation       `json:"operations"`
	Actions     []string          `json:"actions,omitempty"`
	Risks       []string          `json:"risks,omitempty"`
	HostLabels  map[string]string `json:"host_labels"`
	Hours       *Hours            `json:"hours,omitempty"`
	Teams       []string          `json:"teams,omitempty"`
	Owners      []string          `json:"owners,omitempty"`
	SourceCIDRs []string          `json:"source_cidrs,omitempty"`
}

// RuleSource is the boundary for a future persistent store. New takes an immutable snapshot.
type RuleSource interface {
	LoadRules(context.Context) ([]Rule, error)
}

type Result struct {
	Decision string   `json:"decision"`
	RuleIDs  []string `json:"rules"`
}

type HostChange struct {
	HostID string
	Before Result
	After  Result
}

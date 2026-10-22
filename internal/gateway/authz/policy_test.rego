package allowops.authz

fixture_input := {"subject": {"id": "alice", "kind": "ldap", "email": "", "roles": ["oncall"], "teams": [], "owner": ""}, "operation": "execute_action", "action": {"name": "restart", "risk": "write"}, "host": {"id": "h1", "labels": {"env": "prod"}}, "env": {"time_ns": 1791864000000000000, "source_ip": "192.0.2.1"}}
fixture_rule := {"id": "allow", "effect": "allow", "roles": ["oncall"], "operations": ["execute_action"], "actions": ["restart"], "host_labels": {"env": "prod"}}

test_default_deny if {
	result == {"decision": "deny", "rules": []} with data.rules as [] with data.bootstrap_admins as [] with input as fixture_input
}

test_allow if {
	result == {"decision": "allow", "rules": ["allow"]} with data.rules as [fixture_rule] with data.bootstrap_admins as [] with input as fixture_input
}

test_deny_precedes_allow if {
	deny := object.union(fixture_rule, {"id": "deny", "effect": "deny"})
	result == {"decision": "deny", "rules": ["allow", "deny"]} with data.rules as [fixture_rule, deny] with data.bootstrap_admins as [] with input as fixture_input
}

test_missing_host_label if {
	i := object.union(object.remove(fixture_input, ["host"]), {"host": {"labels": {}}})
	result.decision == "deny" with data.rules as [fixture_rule] with data.bootstrap_admins as [] with input as i
}

test_execution_does_not_grant_console if {
	i := object.union(fixture_input, {"operation": "modify_policy"})
	result.decision == "deny" with data.rules as [fixture_rule] with data.bootstrap_admins as [] with input as i
}

test_hours_use_input_time if {
	r := object.union(fixture_rule, {"hours": {"from": 9, "to": 21}})
	allowed := object.union(fixture_input, {"env": {"time_ns": time.parse_rfc3339_ns("2026-10-13T09:00:00+08:00"), "source_ip": "192.0.2.1"}})
	denied := object.union(fixture_input, {"env": {"time_ns": time.parse_rfc3339_ns("2026-10-13T21:00:00+08:00"), "source_ip": "192.0.2.1"}})
	result.decision == "allow" with data.rules as [r] with data.bootstrap_admins as [] with input as allowed
	result.decision == "deny" with data.rules as [r] with data.bootstrap_admins as [] with input as denied
}

test_risk_alternative_selector if {
	r := object.union(fixture_rule, {"actions": [], "risks": ["write"]})
	result.decision == "allow" with data.rules as [r] with data.bootstrap_admins as [] with input as fixture_input
}

test_bootstrap_overrides_policy_deny if {
	i := object.union(fixture_input, {"operation": "modify_policy"})
	r := object.union(fixture_rule, {"effect": "deny", "roles": ["*"], "operations": ["modify_policy"]})
	result == {"decision": "allow", "rules": ["bootstrap_admins"]} with data.rules as [r] with data.bootstrap_admins as ["alice"] with input as i
}

test_bootstrap_does_not_evaluate_policy_conditions if {
	i := object.union(fixture_input, {"operation": "modify_policy", "env": {"source_ip": "invalid"}})
	r := object.union(fixture_rule, {"effect": "deny", "roles": ["*"], "operations": ["modify_policy"], "source_cidrs": ["192.0.2.0/24"]})
	result == {"decision": "allow", "rules": ["bootstrap_admins"]} with data.rules as [r] with data.bootstrap_admins as ["alice"] with input as i
}

test_service_account_cannot_use_bootstrap if {
	i := object.union(fixture_input, {"operation": "modify_policy", "subject": {"id": "alice", "kind": "service_account", "email": "alice", "roles": []}})
	result.decision == "deny" with data.rules as [] with data.bootstrap_admins as ["alice"] with input as i
}

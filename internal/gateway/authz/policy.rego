package allowops.authz

matched contains rule if {
	some rule in data.rules
	input.operation in rule.operations
	role_ok(rule)
	action_ok(rule)
	host_ok(rule)
	time_ok(rule)
	team_ok(rule)
	owner_ok(rule)
	source_ok(rule)
}

role_ok(rule) if "*" in rule.roles

role_ok(rule) if {
	some role in input.subject.roles
	role in rule.roles
}

# execute_action, view_catalog, view_jobs and view_output apply a rule's
# actions/risks. A view request without an action (a global check) is not
# filtered for allow rules; deny rules scoped by actions/risks do not match it.
# Other operations ignore actions/risks.
action_filtered_operations := {"execute_action", "view_catalog", "view_jobs", "view_output"}

action_ok(rule) if not input.operation in action_filtered_operations

# A global view check (no action) matches only allow rules when the rule is
# scoped by actions or risks, so a scoped deny does not block the whole list.
action_ok(rule) if {
	input.operation != "execute_action"
	input.action.name == ""
	rule.effect == "allow"
}

action_ok(rule) if {
	input.operation in action_filtered_operations
	count(object.get(rule, "actions", [])) == 0
	count(object.get(rule, "risks", [])) == 0
}

action_ok(rule) if {
	input.operation in action_filtered_operations
	input.action.name in object.get(rule, "actions", [])
}

action_ok(rule) if {
	input.operation in action_filtered_operations
	"*" in object.get(rule, "actions", [])
}

action_ok(rule) if {
	input.operation in action_filtered_operations
	input.action.risk in object.get(rule, "risks", [])
}

host_ok(rule) if not rule.host_labels
host_ok(rule) if rule.host_labels == null
host_ok(rule) if {
	every k, v in rule.host_labels { input.host.labels[k] == v }
}

time_ok(rule) if not rule.hours

time_ok(rule) if {
	hour := time.clock([input.env.time_ns, object.get(rule.hours, "timezone", "Asia/Shanghai")])[0]
	hour >= rule.hours.from
	hour < rule.hours.to
}

team_ok(rule) if count(object.get(rule, "teams", [])) == 0

team_ok(rule) if {
	some team in input.subject.teams
	team in rule.teams
}

owner_ok(rule) if count(object.get(rule, "owners", [])) == 0
owner_ok(rule) if input.subject.owner in rule.owners

source_ok(rule) if count(object.get(rule, "source_cidrs", [])) == 0

source_ok(rule) if {
	some cidr in rule.source_cidrs
	net.cidr_contains(cidr, input.env.source_ip)
}

bootstrap if {
	input.operation == "modify_policy"
	input.subject.kind == "ldap"
	input.subject.id != ""
	input.subject.id in data.bootstrap_admins
}

bootstrap if {
	input.operation == "modify_policy"
	input.subject.kind == "oidc"
	input.subject.email != ""
	input.subject.email in data.bootstrap_admins
}

effects := {rule.effect | some rule in matched}

decision := "deny" if {
	"deny" in effects
} else := "allow" if {
	"allow" in effects
}

else := "deny"

rule_ids := union({object.keys(object.get(rule, "ids", {rule.id: true})) | some rule in matched})

result := {"decision": "allow", "rules": ["bootstrap_admins"]} if {
	bootstrap
}

else := {"decision": decision, "rules": sort(rule_ids)}

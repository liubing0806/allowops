package authz

// DefaultRules creates fresh rule data for the five built-in roles.
func DefaultRules() []Rule {
	// Only admin receives default execution permissions for all hosts and actions (design A7).
	const defaultAdminCanExecute = true
	rules := []Rule{
		{ID: "default:admin", Effect: "allow", Roles: []string{"admin"}, Operations: []Operation{ModifyPolicy, ManageServiceAccounts, ManageHosts, CreateJoinToken, ManageUserRoles, PublishCatalog, ViewHosts, ViewCatalog, ViewJobs, ViewOutput, ViewAudit, ViewSystem}},
		{ID: "default:operator", Effect: "allow", Roles: []string{"operator"}, Operations: []Operation{ManageHosts, CreateJoinToken, ViewHosts, ViewJobs, ViewSystem}},
		{ID: "default:auditor", Effect: "allow", Roles: []string{"auditor"}, Operations: []Operation{ViewAudit, ViewJobs, ViewOutput}},
		{ID: "default:viewer", Effect: "allow", Roles: []string{"viewer"}, Operations: []Operation{ViewHosts, ViewCatalog, ViewJobs}},
		{ID: "default:publisher", Effect: "allow", Roles: []string{"publisher"}, Operations: []Operation{PublishCatalog}},
	}
	if defaultAdminCanExecute {
		rules[0].Operations = append(rules[0].Operations, ExecuteAction)
		rules[0].Actions = []string{"*"}
	}
	return rules
}

package authz

import (
	"errors"
	"regexp"
	"slices"
)

type ApprovalConfig struct {
	ApproverRoles     []string `json:"approver_roles,omitempty"`
	MinApprovals      int      `json:"min_approvals,omitempty"`
	TTLSeconds        int      `json:"ttl_seconds,omitempty"`
	AllowOwnerApprove bool     `json:"allow_owner_approve,omitempty"`
}

type EffectiveApproval struct {
	RequiredApproverRoleSets [][]string `json:"required_approver_role_sets,omitempty"`
	MinApprovals             int        `json:"min_approvals"`
	TTLSeconds               int        `json:"ttl_seconds,omitempty"`
	AllowOwnerApprove        bool       `json:"allow_owner_approve,omitempty"`
}

var approverRolePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// ValidateApproval checks approval-specific constraints. Zero counts and TTLs
// represent omitted values.
func (r Rule) ValidateApproval() error {
	if r.Effect != "require_approval" {
		if r.Approval != nil {
			return errors.New("approval config requires require_approval effect")
		}
		return nil
	}
	if len(r.Operations) != 1 || r.Operations[0] != ExecuteAction {
		return errors.New("require_approval must have execute_action as its sole operation")
	}
	a := r.Approval
	if a == nil {
		return nil
	}
	if a.MinApprovals < 0 || a.MinApprovals > 5 {
		return errors.New("min_approvals must be omitted or between 1 and 5")
	}
	if a.TTLSeconds != 0 && (a.TTLSeconds < 60 || a.TTLSeconds > 604800) {
		return errors.New("ttl_seconds must be omitted or between 60 and 604800")
	}
	if len(a.ApproverRoles) > 16 {
		return errors.New("approver_roles must contain at most 16 roles")
	}
	seen := make(map[string]bool, len(a.ApproverRoles))
	for _, role := range a.ApproverRoles {
		if !approverRolePattern.MatchString(role) || seen[role] {
			return errors.New("approver_roles must contain distinct role names matching ^[a-zA-Z0-9._-]{1,64}$")
		}
		seen[role] = true
	}
	return nil
}

// MergeEffectiveApprovals combines the requirements from all non-nil items.
// Each role set remains a separate requirement. The result owns its role slices.
func MergeEffectiveApprovals(items []*EffectiveApproval) *EffectiveApproval {
	var merged *EffectiveApproval
	for _, item := range items {
		if item == nil {
			continue
		}
		if merged == nil {
			merged = &EffectiveApproval{AllowOwnerApprove: true}
		}
		merged.MinApprovals = max(merged.MinApprovals, item.MinApprovals)
		if item.TTLSeconds != 0 && (merged.TTLSeconds == 0 || item.TTLSeconds < merged.TTLSeconds) {
			merged.TTLSeconds = item.TTLSeconds
		}
		merged.AllowOwnerApprove = merged.AllowOwnerApprove && item.AllowOwnerApprove
		for _, roles := range item.RequiredApproverRoleSets {
			if len(roles) > 0 {
				roles = slices.Clone(roles)
				slices.Sort(roles)
				merged.RequiredApproverRoleSets = append(merged.RequiredApproverRoleSets, slices.Compact(roles))
			}
		}
	}
	if merged != nil {
		roleSets := merged.RequiredApproverRoleSets
		slices.SortFunc(roleSets, slices.Compare[[]string])
		merged.RequiredApproverRoleSets = slices.CompactFunc(roleSets, slices.Equal[[]string, string])
	}
	return merged
}

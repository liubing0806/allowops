// Package notifier defines approval events delivered by gateway plugins.
package notifier

import (
	"context"
	"time"
)

type EventType string

const (
	EventApprovalRequested EventType = "approval.requested"
	EventApprovalApproved  EventType = "approval.approved"
	EventApprovalRejected  EventType = "approval.rejected"
	EventApprovalExpired   EventType = "approval.expired"
	EventApprovalCancelled EventType = "approval.cancelled"
)

type Event struct {
	Type                     EventType  `json:"type"`
	EventID                  string     `json:"event_id"`
	At                       time.Time  `json:"at"`
	ApprovalID               string     `json:"approval_id"`
	JobID                    string     `json:"job_id"`
	Action                   string     `json:"action"`
	Risk                     string     `json:"risk"`
	Requester                string     `json:"requester"`
	TargetCount              int        `json:"target_count"`
	SampleHosts              []string   `json:"sample_hosts,omitempty"`
	RequiredApproverRoleSets [][]string `json:"required_approver_role_sets,omitempty"`
	MinApprovals             int        `json:"min_approvals"`
	ApprovedCount            int        `json:"approved_count"`
	ExpiresAt                time.Time  `json:"expires_at"`
	ConsoleURL               string     `json:"console_url"`
	Actor                    string     `json:"actor,omitempty"`
	Status                   string     `json:"status"`
}

type Sender interface {
	Send(ctx context.Context, event Event) error
}

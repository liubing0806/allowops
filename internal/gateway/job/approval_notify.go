package job

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/store/db"
)

// ApprovalNotifier is configured before the service starts. Notifications are
// post-commit and best effort. Implementations may receive events out of order.
type ApprovalNotifier interface {
	NotifyApproval(context.Context, ApprovalNotification)
}

type ApprovalNotification struct {
	Type, EventID, ApprovalID, JobID, Action, Risk, Requester, Actor, ConsoleURL string
	Sequence                                                                     int64
	At, ExpiresAt                                                                time.Time
	TargetCount                                                                  int
	SampleHosts                                                                  []string
	RequiredApproverRoleSets                                                     [][]string
	MinApprovals, ApprovedCount                                                  int
	Status                                                                       v1.ApprovalStatus
}

func (s *Service) notifyApproval(row db.ApprovalRequest, event string) {
	notifier := s.ApprovalNotifier
	if notifier == nil {
		return
	}
	targets, _, err := approvalTargets(row)
	if err != nil {
		return
	}
	constraints, err := approvalConstraints(row)
	if err != nil {
		return
	}
	at := row.CreatedAt.Time
	if row.DecidedAt.Valid {
		at = row.DecidedAt.Time
	}
	notification := ApprovalNotification{
		Type: "approval." + event, EventID: fmt.Sprintf("%s:%d", row.ApprovalID, row.NotifySeq), Sequence: row.NotifySeq,
		ApprovalID: row.ApprovalID, JobID: row.JobID, Action: row.Action, Risk: row.ActionRisk,
		Requester: row.RequesterSubjectID, Actor: row.DecidedBy, ConsoleURL: s.approvalURL(row.ApprovalID),
		At: at, ExpiresAt: row.ExpiresAt.Time, TargetCount: len(targets),
		RequiredApproverRoleSets: constraints.RequiredApproverRoleSets,
		MinApprovals:             int(row.MinApprovals), ApprovedCount: int(row.ApprovedCount), Status: v1.ApprovalStatus(row.Status),
	}
	for _, target := range targets[:min(len(targets), 5)] {
		notification.SampleHosts = append(notification.SampleHosts, target.Hostname)
	}
	go func() {
		defer func() {
			if recover() != nil {
				slog.Error("approval notifier panicked", "approval_id", row.ApprovalID)
			}
		}()
		ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
		defer cancel()
		notifier.NotifyApproval(ctx, notification)
	}()
}

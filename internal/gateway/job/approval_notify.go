package job

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/store/db"
)

// ApprovalNotifier is configured before the service starts. Notifications are
// post-commit and best effort. Implementations may receive events out of order
// and must stop on context cancellation.
type ApprovalNotifier interface {
	NotifyApproval(context.Context, ApprovalNotification)
}

// ApprovalNotifierFunc adapts a delivery function whose outcome is persisted.
type ApprovalNotifierFunc func(context.Context, ApprovalNotification) (status, errCode string)

func (f ApprovalNotifierFunc) NotifyApproval(ctx context.Context, event ApprovalNotification) {
	f(ctx, event)
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

const (
	approvalNotificationQueueSize = 256
	approvalNotificationWorkers   = 2
	approvalNotificationTimeout   = 5 * time.Second
)

type approvalNotifications struct {
	mu       sync.Mutex
	stopped  bool
	pending  chan ApprovalNotification
	overflow chan db.UpdateApprovalNotificationParams
	done     chan struct{}
	workers  sync.WaitGroup
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
	s.enqueueApprovalNotification(notifier, notification)
}

func (s *Service) enqueueApprovalNotification(notifier ApprovalNotifier, event ApprovalNotification) {
	q := &s.notifications
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.stopped {
		return
	}
	if q.pending == nil {
		q.pending = make(chan ApprovalNotification, approvalNotificationQueueSize)
		q.overflow = make(chan db.UpdateApprovalNotificationParams, approvalNotificationQueueSize)
		q.done = make(chan struct{})
		for range approvalNotificationWorkers {
			q.workers.Go(func() {
				for event := range q.pending {
					if s.ctx.Err() != nil {
						return
					}
					s.deliverApprovalNotification(notifier, event)
				}
			})
		}
		q.workers.Go(func() {
			for update := range q.overflow {
				if s.ctx.Err() != nil {
					return
				}
				s.updateApprovalNotification(update)
			}
		})
	}
	select {
	case q.pending <- event:
	default:
		// Record overload independently of the workers waiting for webhook I/O.
		select {
		case q.overflow <- db.UpdateApprovalNotificationParams{
			ApprovalID: event.ApprovalID, NotifySeq: event.Sequence, NotifyStatus: "failed", NotifyError: "NOTIFY_QUEUE_FULL",
		}:
		default:
			slog.Warn("approval notification queue full and status backlog exhausted", "approval_id", event.ApprovalID)
		}
	}
}

func (s *Service) deliverApprovalNotification(notifier ApprovalNotifier, event ApprovalNotification) {
	update := db.UpdateApprovalNotificationParams{ApprovalID: event.ApprovalID, NotifySeq: event.Sequence}
	defer func() {
		if recover() != nil {
			slog.Error("approval notifier panicked", "approval_id", event.ApprovalID)
			update.NotifyStatus, update.NotifyError = "failed", "NOTIFY_PANIC"
		}
		if update.NotifyStatus != "" {
			s.updateApprovalNotification(update)
		}
	}()
	ctx, cancel := context.WithTimeout(s.ctx, approvalNotificationTimeout)
	defer cancel()
	if deliver, ok := notifier.(ApprovalNotifierFunc); ok {
		update.NotifyStatus, update.NotifyError = deliver(ctx, event)
	} else {
		notifier.NotifyApproval(ctx, event)
	}
}

func (s *Service) updateApprovalNotification(update db.UpdateApprovalNotificationParams) {
	ctx, cancel := context.WithTimeout(s.ctx, approvalNotificationTimeout)
	defer cancel()
	// Transitions advance notify_seq before delivery. The existing equality
	// guard only records outcomes for the currently committed event.
	if _, err := s.Store.Queries.UpdateApprovalNotification(ctx, update); err != nil && s.ctx.Err() == nil {
		slog.Warn("approval notification status update failed", "approval_id", update.ApprovalID)
	}
}

// DrainNotifications stops admission and waits for accepted deliveries and
// overflow status updates while the service and its notifier are still active.
func (s *Service) DrainNotifications(ctx context.Context) {
	done := s.stopNotifications()
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (s *Service) stopNotifications() <-chan struct{} {
	q := &s.notifications
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.stopped {
		q.stopped = true
		if q.pending != nil {
			close(q.pending)
			close(q.overflow)
			go func() {
				q.workers.Wait()
				close(q.done)
			}()
		}
	}
	return q.done
}

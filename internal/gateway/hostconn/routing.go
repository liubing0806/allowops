package hostconn

import (
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/store/db"
	"google.golang.org/protobuf/proto"
)

// Router is P6's dispatch boundary. Send waits for TaskCompleted metadata only.
// Streaming output/events and disconnect events belong to the owner's Hooks.
// No request survives its connection generation or gets replayed after reconnect.
type Router interface {
	Send(context.Context, string, *v1.ConnectResponse) (*v1.TaskCompleted, error)
}

func taskID(m *v1.ConnectResponse) string {
	if t := m.GetTask(); t != nil {
		return t.TaskId
	}
	if c := m.GetCancel(); c != nil {
		return c.TaskId
	}
	return ""
}

func (s *Service) Send(ctx context.Context, host string, message *v1.ConnectResponse) (*v1.TaskCompleted, error) {
	return s.sendToConnection(ctx, host, "", message)
}

// SendToConnection binds dispatch/cancellation to the generation reserved by P6.
// A replacement connection is offline for that task and must not execute it.
func (s *Service) SendToConnection(ctx context.Context, host, connectionID string, message *v1.ConnectResponse) (*v1.TaskCompleted, error) {
	if connectionID == "" {
		return nil, errors.New("connection ID required")
	}
	return s.sendToConnection(ctx, host, connectionID, message)
}

func (s *Service) sendToConnection(ctx context.Context, host, expectedConnection string, message *v1.ConnectResponse) (*v1.TaskCompleted, error) {
	if s.draining.Load() && message.GetCancel() == nil {
		return nil, store.ErrOffline
	}
	if message == nil || taskID(message) == "" {
		return nil, errors.New("task or cancellation with task ID required")
	}
	raw, err := proto.Marshal(message)
	if err != nil {
		return nil, err
	}
	if len(raw) > s.Config.MessageBytes {
		return nil, store.ErrCapacity
	}
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.Store.Queries.WithTx(tx)
	// One global capacity lock also reserves space for a maximum-sized response.
	if err := q.LockMailboxCapacity(ctx); err != nil {
		return nil, err
	}
	if err := q.DeleteExpiredMessages(ctx); err != nil {
		return nil, err
	}
	usage, err := q.GetMailboxUsage(ctx)
	if err != nil {
		return nil, err
	}
	if usage.Count >= s.Config.MailboxRows || usage.Column2+int64(len(raw))+(1<<20) > s.Config.MailboxBytes {
		return nil, store.ErrCapacity
	}
	current, err := q.GetOnlineHostConnectionForShare(ctx, host)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrOffline
	}
	if err != nil {
		return nil, err
	}
	connectionID := current.String
	if expectedConnection != "" && connectionID != expectedConnection {
		return nil, store.ErrOffline
	}
	id := rand.Text()
	expires := time.Now().Add(s.Config.MailboxTTL)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	// G46 applies only to generation-bound task messages. The original Send and
	// cancellation messages retain the configured transient mailbox lifetime.
	if expectedConnection != "" && message.GetTask() != nil {
		if deadline, ok := ctx.Deadline(); ok {
			expires = deadline
		}
	}
	if err := insertMessage(ctx, tx, id, s.InstanceID, host, connectionID, raw, expires); err != nil {
		return nil, err
	}
	if err := store.Notify(ctx, tx, "message:"+id); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Store.Queries.DeleteGatewayMessage(cleanup, id)
		s.forgetPending(host, connectionID, taskID(message), id)
	}()
	// NOTIFY wakes the owner. The origin reads the small final metadata using a
	// bounded poll, so a missed completion notification cannot lose a result.
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, store.ErrOffline
		case <-ticker.C:
			if time.Now().After(expires) {
				// A mailbox that expires with the caller's own deadline is the
				// caller's timeout, not evidence that the host is offline.
				if deadline, ok := ctx.Deadline(); ok && !deadline.After(expires) {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					return nil, context.DeadlineExceeded
				}
				return nil, store.ErrOffline
			}
			result, err := s.Store.Queries.GetGatewayMessageResult(ctx, id)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, store.ErrOffline
			}
			if err != nil {
				return nil, err
			}
			if result.Failure != "" {
				if result.Failure == "capacity" {
					return nil, store.ErrCapacity
				}
				return nil, store.ErrOffline
			}
			if result.Response != nil {
				completed := new(v1.TaskCompleted)
				if err := proto.Unmarshal(result.Response, completed); err != nil {
					return nil, err
				}
				return completed, nil
			}
		}
	}
}

// forgetPending drops a deleted mailbox row from the local connection's in-flight
// list. Otherwise a sender that timed out keeps counting against the per-task limit.
func (s *Service) forgetPending(host, connectionID, task, mailbox string) {
	s.mu.Lock()
	c := s.connections[host]
	s.mu.Unlock()
	if c == nil || c.id != connectionID {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if kept := slices.DeleteFunc(c.pending[task], func(id string) bool { return id == mailbox }); len(kept) > 0 {
		c.pending[task] = kept
	} else {
		delete(c.pending, task)
	}
}

func (s *Service) notification(payload string) {
	switch {
	case strings.HasPrefix(payload, "host:"):
		host := strings.TrimPrefix(payload, "host:")
		s.mu.Lock()
		c := s.connections[host]
		s.mu.Unlock()
		if c == nil {
			return
		}
		h, err := s.Store.Queries.GetHost(s.ctx, host)
		if err != nil || h.CertificateStatus != "active" || h.ConnectionID.String != c.id {
			c.cancel()
		}
	case strings.HasPrefix(payload, "catalog:"):
		for _, c := range s.snapshot() {
			s.catalogs(c)
		}
	case strings.HasPrefix(payload, "message:"):
		s.dispatch(strings.TrimPrefix(payload, "message:"))
	}
}

func (s *Service) dispatch(id string) {
	message, err := s.Store.Queries.GetLiveGatewayMessage(s.ctx, id)
	if err != nil {
		return
	}
	s.mu.Lock()
	c := s.connections[message.HostID]
	s.mu.Unlock()
	if c == nil || c.id != message.ConnectionID {
		return
	}
	m := new(v1.ConnectResponse)
	if err := proto.Unmarshal(message.Request, m); err != nil {
		c.cancel()
		return
	}
	if (s.draining.Load() && m.GetCancel() == nil) || s.enqueue(c, outbound{message: m, mailbox: id}) != nil {
		_ = s.failConnection(s.ctx, c.id)
	}
}

func (s *Service) write(c *connection, stream *connect.BidiStream[v1.ConnectRequest, v1.ConnectResponse], item outbound) error {
	if item.mailbox == "" {
		return s.send(c.ctx, func() error { return stream.Send(item.message) })
	}
	if s.draining.Load() && item.message.GetCancel() == nil {
		return store.ErrOffline
	}
	tx, err := s.Store.Pool.Begin(c.ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(c.ctx)
	q := s.Store.Queries.WithTx(tx)
	// Hold FOR SHARE until the actual write. A newer connection cannot commit
	// ownership while a message is being written to the old generation.
	current, err := q.GetActiveHostConnectionForShare(c.ctx, c.identity.HostID)
	if err != nil || current.String != c.id {
		return store.ErrOffline
	}
	live, err := messageLive(c.ctx, tx, item.mailbox, c.id)
	if err != nil {
		return err
	}
	if !live {
		return nil
	}
	if task := item.message.GetTask(); task != nil {
		// Cancel/recovery can commit on another instance after reservation or
		// enqueue. Order the actual stream write against those transactions,
		// taking the job lock before the task lock just as they do.
		job, err := q.GetJobDispatchStateForShare(c.ctx, task.JobId)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		// Standalone P4 routing predates persisted jobs. Only an explicit
		// missing job preserves that path; all other SQL errors fail closed.
		if !errors.Is(err, pgx.ErrNoRows) {
			live = job.Status <= 2 && !job.CancelRequested
			if live {
				var state db.GetTaskDispatchStateForShareRow
				state, err = q.GetTaskDispatchStateForShare(c.ctx, db.GetTaskDispatchStateForShareParams{JobID: task.JobId, TaskID: task.TaskId})
				if err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
				live = err == nil && state.Status <= 2 && state.Dispatched && state.HostID == c.identity.HostID && state.ConnectionID == c.id
			}
			if !live {
				if err := q.FailGatewayMessageOffline(c.ctx, item.mailbox); err != nil {
					return err
				}
				return tx.Commit(c.ctx)
			}
		}
	}

	id := taskID(item.message)
	c.mu.Lock()
	existing := c.pending[id]
	if (len(existing) > 0 && item.message.GetCancel() == nil) || (len(existing) == 0 && len(c.pending) >= c.maxInflight) || len(existing) >= 2 {
		c.mu.Unlock()
		err := failMessageCapacity(c.ctx, tx, item.mailbox)
		if err != nil {
			return err
		}
		return tx.Commit(c.ctx)
	}
	c.pending[id] = append(existing, item.mailbox)
	c.mu.Unlock()
	if err := s.send(c.ctx, func() error { return stream.Send(item.message) }); err != nil {
		return err
	}
	return tx.Commit(c.ctx)
}

func (s *Service) complete(c *connection, result *v1.TaskCompleted) error {
	c.mu.Lock()
	ids := c.pending[result.TaskId]
	delete(c.pending, result.TaskId)
	c.mu.Unlock()
	if len(ids) == 0 {
		return nil
	} // Unsolicited results are handled by P6's callback.
	raw, err := proto.Marshal(result)
	if err != nil {
		return err
	}
	return s.Store.Queries.CompleteGatewayMessages(c.ctx, db.CompleteGatewayMessagesParams{Column1: ids, Response: raw, ConnectionID: c.id, HostID: c.identity.HostID})
}

func (s *Service) failConnection(ctx context.Context, generation string) error {
	return s.Store.Queries.FailConnectionMessages(ctx, generation)
}

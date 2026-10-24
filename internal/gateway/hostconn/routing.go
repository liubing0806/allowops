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
	"github.com/jackc/pgx/v5/pgtype"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/store/db"
	"google.golang.org/protobuf/proto"
)

// Router is the job module's dispatch boundary (design P6). Send waits for TaskCompleted metadata only.
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

// SendToConnection binds dispatch/cancellation to the generation reserved by the job module (design P6).
// A replacement connection is offline for that task and must not execute it.
func (s *Service) SendToConnection(ctx context.Context, host, connectionID string, message *v1.ConnectResponse) (*v1.TaskCompleted, error) {
	if connectionID == "" {
		return nil, errors.New("connection ID required")
	}
	return s.sendToConnection(ctx, host, connectionID, message)
}

func (s *Service) sendToConnection(ctx context.Context, host, expectedConnection string, message *v1.ConnectResponse) (*v1.TaskCompleted, error) {
	raw, err := s.encodeOutgoing(message)
	if err != nil {
		return nil, err
	}
	id, connectionID, expires, err := s.reserveMailbox(ctx, host, expectedConnection, message, raw)
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Store.Queries.DeleteGatewayMessage(cleanup, id)
		s.forgetPending(host, connectionID, taskID(message), id)
	}()
	return s.awaitMailboxResult(ctx, id, expires)
}

// encodeOutgoing rejects drained, malformed and oversized messages before any
// database work.
func (s *Service) encodeOutgoing(message *v1.ConnectResponse) ([]byte, error) {
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
	return raw, nil
}

// reserveMailbox runs the capacity checks, the online-connection check, the
// mailbox insert and NOTIFY in one transaction, and commits it.
func (s *Service) reserveMailbox(ctx context.Context, host, expectedConnection string, message *v1.ConnectResponse, raw []byte) (id, connectionID string, expires time.Time, err error) {
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return "", "", time.Time{}, err
	}
	defer tx.Rollback(ctx)
	q := s.Store.Queries.WithTx(tx)
	// One global capacity lock also reserves space for a maximum-sized response.
	if err := q.LockMailboxCapacity(ctx); err != nil {
		return "", "", time.Time{}, err
	}
	if err := q.DeleteExpiredMessages(ctx); err != nil {
		return "", "", time.Time{}, err
	}
	usage, err := q.GetMailboxUsage(ctx)
	if err != nil {
		return "", "", time.Time{}, err
	}
	if usage.Count >= s.Config.MailboxRows || usage.Column2+int64(len(raw))+(1<<20) > s.Config.MailboxBytes {
		return "", "", time.Time{}, store.ErrCapacity
	}
	current, err := q.GetOnlineHostConnectionForShare(ctx, host)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", time.Time{}, store.ErrOffline
	}
	if err != nil {
		return "", "", time.Time{}, err
	}
	connectionID = current.String
	if expectedConnection != "" && connectionID != expectedConnection {
		return "", "", time.Time{}, store.ErrOffline
	}
	id = rand.Text()
	expires = time.Now().Add(s.Config.MailboxTTL)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	// Task messages bound to a connection generation wait until the task deadline (design G46). The original Send and
	// cancellation messages retain the configured transient mailbox lifetime.
	if expectedConnection != "" && message.GetTask() != nil {
		if deadline, ok := ctx.Deadline(); ok {
			expires = deadline
		}
	}
	if err := insertMessage(ctx, tx, id, s.InstanceID, host, connectionID, raw, expires); err != nil {
		return "", "", time.Time{}, err
	}
	if err := store.Notify(ctx, tx, "message:"+id); err != nil {
		return "", "", time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", time.Time{}, err
	}
	return id, connectionID, expires, nil
}

// awaitMailboxResult waits for the owner's completion. NOTIFY wakes the owner.
// The origin reads the small final metadata using a bounded poll, so a missed
// completion notification cannot lose a result.
func (s *Service) awaitMailboxResult(ctx context.Context, id string, expires time.Time) (*v1.TaskCompleted, error) {
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
			completed, done, err := s.pollMailboxResult(ctx, id)
			if done || err != nil {
				return completed, err
			}
		}
	}
}

// pollMailboxResult reads the mailbox row once. done is false while the owner
// has not yet recorded a response or failure.
func (s *Service) pollMailboxResult(ctx context.Context, id string) (completed *v1.TaskCompleted, done bool, err error) {
	result, err := s.Store.Queries.GetGatewayMessageResult(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, true, store.ErrOffline
	}
	if err != nil {
		return nil, true, err
	}
	if result.Failure != "" {
		if result.Failure == "capacity" {
			return nil, true, store.ErrCapacity
		}
		return nil, true, store.ErrOffline
	}
	if result.Response == nil {
		return nil, false, nil
	}
	completed = new(v1.TaskCompleted)
	if err := proto.Unmarshal(result.Response, completed); err != nil {
		return nil, true, err
	}
	return completed, true, nil
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

// reconcilePending drops pending mailbox IDs whose gateway_messages row no longer
// exists, which only the connection owner can detect when the sender ran on another
// instance: that sender deletes the row on timeout or cancellation, but forgetPending
// reaches only the sender's own connection map. The agent ignores a cancel for a task
// it does not know, so such an entry would otherwise stay until the connection ends
// and count against MaxInflight.
//
// The rule is deliberately narrower than "the row is gone". An ID is dropped only if
//   - it is not the first in its task's list and its row is gone: write admits a second
//     ID only for a cancel, so the first ID is the assignment and later ones are
//     cancels, and a stale cancel must not block a retried cancel (limit of two); or
//   - its row is gone and the task is not active on this connection per the database
//     (finished, absent, or owned by another connection).
//
// The ID of a task that is still executing is kept even when its sender is gone, so
// the task keeps occupying its slot until TaskCompleted arrives. A mailbox that is
// added after the snapshot is never considered; its row exists when write adds it.
func (s *Service) reconcilePending(ctx context.Context, c *connection) error {
	c.mu.Lock()
	var ids, tasks []string
	for task, mailboxes := range c.pending {
		tasks = append(tasks, task)
		ids = append(ids, mailboxes...)
	}
	c.mu.Unlock()
	if len(ids) == 0 {
		return nil
	}
	found, err := s.Store.Queries.ListExistingGatewayMessageIDs(ctx, ids)
	if err != nil {
		return err
	}
	exists := make(map[string]bool, len(found))
	for _, id := range found {
		exists[id] = true
	}
	missing := map[string]bool{}
	for _, id := range ids {
		if !exists[id] {
			missing[id] = true
		}
	}
	if len(missing) == 0 {
		return nil
	}
	// The status predicate matches tasks_host_connection. A task only leaves the
	// active states, so a task read as inactive here cannot become active later.
	activeTasks, err := s.Store.Queries.ListActiveTaskIDsOnConnection(ctx, db.ListActiveTaskIDsOnConnectionParams{TaskIds: tasks, HostID: c.identity.HostID, ConnectionID: pgtype.Text{String: c.id, Valid: true}})
	if err != nil {
		return err
	}
	active := make(map[string]bool, len(activeTasks))
	for _, task := range activeTasks {
		active[task] = true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for task, mailboxes := range c.pending {
		i := -1
		kept := slices.DeleteFunc(slices.Clone(mailboxes), func(id string) bool {
			i++
			return missing[id] && (i > 0 || !active[task])
		})
		if len(kept) == len(mailboxes) {
			continue
		}
		if len(kept) > 0 {
			c.pending[task] = kept
		} else {
			delete(c.pending, task)
		}
	}
	return nil
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
		live, err := taskStillDispatchable(c, q, task)
		if err != nil {
			return err
		}
		if !live {
			if err := q.FailGatewayMessageOffline(c.ctx, item.mailbox); err != nil {
				return err
			}
			return tx.Commit(c.ctx)
		}
	}
	if !reservePending(c, item) {
		err := failMessageCapacity(c.ctx, tx, item.mailbox)
		if err != nil {
			return err
		}
		return tx.Commit(c.ctx)
	}
	if err := s.send(c.ctx, func() error { return stream.Send(item.message) }); err != nil {
		return err
	}
	return tx.Commit(c.ctx)
}

// taskStillDispatchable orders the stream write against cancel/recovery, which
// can commit on another instance after reservation or enqueue. It takes the job
// lock before the task lock just as they do, and keeps both until the caller's
// transaction ends.
func taskStillDispatchable(c *connection, q *db.Queries, task *v1.TaskAssignment) (bool, error) {
	job, err := q.GetJobDispatchStateForShare(c.ctx, task.JobId)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	// Standalone host routing predates persisted jobs (design P4). Only an explicit
	// missing job preserves that path; all other SQL errors fail closed.
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	if job.Status > 2 || job.CancelRequested {
		return false, nil
	}
	state, err := q.GetTaskDispatchStateForShare(c.ctx, db.GetTaskDispatchStateForShareParams{JobID: task.JobId, TaskID: task.TaskId})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	return err == nil && state.Status <= 2 && state.Dispatched && state.HostID == c.identity.HostID && state.ConnectionID == c.id, nil
}

// reservePending records the mailbox row as in flight on c. It returns false,
// leaving c unchanged, when the per-task or per-connection limit is reached.
func reservePending(c *connection, item outbound) bool {
	id := taskID(item.message)
	c.mu.Lock()
	defer c.mu.Unlock()
	existing := c.pending[id]
	if (len(existing) > 0 && item.message.GetCancel() == nil) || (len(existing) == 0 && len(c.pending) >= c.maxInflight) || len(existing) >= 2 {
		return false
	}
	c.pending[id] = append(existing, item.mailbox)
	return true
}

func (s *Service) complete(c *connection, result *v1.TaskCompleted) error {
	c.mu.Lock()
	ids := c.pending[result.TaskId]
	delete(c.pending, result.TaskId)
	c.mu.Unlock()
	if len(ids) == 0 {
		return nil
	} // Unsolicited results are handled by the job module's callback (design P6).
	raw, err := proto.Marshal(result)
	if err != nil {
		return err
	}
	return s.Store.Queries.CompleteGatewayMessages(c.ctx, db.CompleteGatewayMessagesParams{Column1: ids, Response: raw, ConnectionID: c.id, HostID: c.identity.HostID})
}

func (s *Service) failConnection(ctx context.Context, generation string) error {
	return s.Store.Queries.FailConnectionMessages(ctx, generation)
}

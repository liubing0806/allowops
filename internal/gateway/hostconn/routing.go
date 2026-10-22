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
	// One global capacity lock also reserves space for a maximum-sized response.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(418002)"); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, "DELETE FROM gateway_messages WHERE expires_at<=now()"); err != nil {
		return nil, err
	}
	var rows, bytes int64
	if err := tx.QueryRow(ctx, "SELECT count(*),COALESCE(sum(octet_length(request)+1048576),0)::bigint FROM gateway_messages").Scan(&rows, &bytes); err != nil {
		return nil, err
	}
	if rows >= s.Config.MailboxRows || bytes+int64(len(raw))+(1<<20) > s.Config.MailboxBytes {
		return nil, store.ErrCapacity
	}
	var connectionID string
	err = tx.QueryRow(ctx, "SELECT connection_id FROM hosts WHERE host_id=$1 AND certificate_status='active' AND instance_id IS NOT NULL FOR SHARE", host).Scan(&connectionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrOffline
	}
	if err != nil {
		return nil, err
	}
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
	if _, err := tx.Exec(ctx, "INSERT INTO gateway_messages(message_id,origin_instance,host_id,connection_id,request,expires_at) VALUES ($1,$2,$3,$4,$5,$6)", id, s.InstanceID, host, connectionID, raw, expires); err != nil {
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
		_, _ = s.Store.Pool.Exec(cleanup, "DELETE FROM gateway_messages WHERE message_id=$1", id)
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
			var response []byte
			var failure string
			err := s.Store.Pool.QueryRow(ctx, "SELECT response,failure FROM gateway_messages WHERE message_id=$1", id).Scan(&response, &failure)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, store.ErrOffline
			}
			if err != nil {
				return nil, err
			}
			if failure != "" {
				if failure == "capacity" {
					return nil, store.ErrCapacity
				}
				return nil, store.ErrOffline
			}
			if response != nil {
				result := new(v1.TaskCompleted)
				if err := proto.Unmarshal(response, result); err != nil {
					return nil, err
				}
				return result, nil
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
	rows, err := s.Store.Pool.Query(ctx, "SELECT message_id FROM gateway_messages WHERE message_id=ANY($1::text[])", ids)
	if err != nil {
		return err
	}
	exists := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		exists[id] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
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
	rows, err = s.Store.Pool.Query(ctx, "SELECT DISTINCT task_id FROM tasks WHERE task_id=ANY($1::text[]) AND host_id=$2 AND connection_id=$3 AND status IN (1,2)", tasks, c.identity.HostID, c.id)
	if err != nil {
		return err
	}
	active := map[string]bool{}
	for rows.Next() {
		var task string
		if err := rows.Scan(&task); err != nil {
			rows.Close()
			return err
		}
		active[task] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
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
	var host, generation string
	var raw []byte
	err := s.Store.Pool.QueryRow(s.ctx, "SELECT host_id,connection_id,request FROM gateway_messages WHERE message_id=$1 AND expires_at>now() AND response IS NULL AND failure=''", id).Scan(&host, &generation, &raw)
	if err != nil {
		return
	}
	s.mu.Lock()
	c := s.connections[host]
	s.mu.Unlock()
	if c == nil || c.id != generation {
		return
	}
	m := new(v1.ConnectResponse)
	if err := proto.Unmarshal(raw, m); err != nil {
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
	// Hold FOR SHARE until the actual write. A newer connection cannot commit
	// ownership while a message is being written to the old generation.
	var current string
	err = tx.QueryRow(c.ctx, "SELECT connection_id FROM hosts WHERE host_id=$1 AND certificate_status='active' FOR SHARE", c.identity.HostID).Scan(&current)
	if err != nil || current != c.id {
		return store.ErrOffline
	}
	var live bool
	if err := tx.QueryRow(c.ctx, "SELECT EXISTS(SELECT 1 FROM gateway_messages WHERE message_id=$1 AND connection_id=$2 AND expires_at>now() AND response IS NULL AND failure='')", item.mailbox, c.id).Scan(&live); err != nil {
		return err
	}
	if !live {
		return nil
	}
	if task := item.message.GetTask(); task != nil {
		// Cancel/recovery can commit on another instance after reservation or
		// enqueue. Order the actual stream write against those transactions,
		// taking the job lock before the task lock just as they do.
		var status int16
		var cancelled bool
		err := tx.QueryRow(c.ctx, "SELECT status,cancel_requested FROM jobs WHERE job_id=$1 FOR SHARE", task.JobId).Scan(&status, &cancelled)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		// Standalone P4 routing predates persisted jobs. Only an explicit
		// missing job preserves that path; all other SQL errors fail closed.
		if !errors.Is(err, pgx.ErrNoRows) {
			live = status <= 2 && !cancelled
			if live {
				var dispatched bool
				var host, generation string
				err = tx.QueryRow(c.ctx, "SELECT status,dispatched,host_id,COALESCE(connection_id,'') FROM tasks WHERE job_id=$1 AND task_id=$2 FOR SHARE", task.JobId, task.TaskId).Scan(&status, &dispatched, &host, &generation)
				if err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
				live = err == nil && status <= 2 && dispatched && host == c.identity.HostID && generation == c.id
			}
			if !live {
				if _, err := tx.Exec(c.ctx, "UPDATE gateway_messages SET failure='offline' WHERE message_id=$1", item.mailbox); err != nil {
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
		_, err := tx.Exec(c.ctx, "UPDATE gateway_messages SET failure='capacity' WHERE message_id=$1", item.mailbox)
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
	_, err = s.Store.Pool.Exec(c.ctx, "UPDATE gateway_messages SET response=$2 WHERE message_id=ANY($1::text[]) AND connection_id=$3 AND expires_at>now() AND response IS NULL AND failure='' AND EXISTS(SELECT 1 FROM hosts WHERE host_id=$4 AND connection_id=$3 AND certificate_status='active')", ids, raw, c.id, c.identity.HostID)
	return err
}

func (s *Service) failConnection(ctx context.Context, generation string) error {
	_, err := s.Store.Pool.Exec(ctx, "UPDATE gateway_messages SET failure='offline' WHERE connection_id=$1 AND response IS NULL", generation)
	return err
}

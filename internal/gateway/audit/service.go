package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Access is supplied by the identity module (design P5). It authenticates the request and authorizes
// view_audit on EVERY call, returning the stable subject bound to API cursors.
// A nil implementation denies access. Middleware may also add context values.
type Access interface {
	Authorize(context.Context, http.Header, string) (string, error)
}

type Service struct {
	Store  *Store
	Access Access
}

func (s *Service) authorize(ctx context.Context, h http.Header) (string, error) {
	if s.Access == nil {
		return "", connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("audit authentication required"))
	}
	subject, err := s.Access.Authorize(ctx, h, "view_audit")
	if err != nil {
		return "", err
	}
	if subject == "" {
		return "", connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("audit authentication required"))
	}
	return subject, nil
}

func rpcError(err error) error {
	switch {
	case errors.Is(err, ErrLimit):
		return connect.NewError(connect.CodeResourceExhausted, ErrLimit)
	case errors.Is(err, ErrInvalid):
		return connect.NewError(connect.CodeInvalidArgument, ErrInvalid)
	case errors.Is(err, ErrUnavailable), errors.Is(err, errMalformedEvent):
		return connect.NewError(connect.CodeFailedPrecondition, ErrUnavailable)
	default:
		return connect.NewError(connect.CodeInternal, fmt.Errorf("audit database operation failed"))
	}
}

type cursor struct {
	Kind, Subject string
	Query         []byte
	Next, Last    uint64
}

func (s *Store) token(c cursor) (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, s.Config.CursorKey)
	mac.Write(data)
	return base64.RawURLEncoding.EncodeToString(append(data, mac.Sum(nil)...)), nil
}

func (s *Store) cursor(token, kind, subject string, query []byte) (cursor, error) {
	var c cursor
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(data) < 32 {
		return c, ErrInvalid
	}
	body, signature := data[:len(data)-32], data[len(data)-32:]
	mac := hmac.New(sha256.New, s.Config.CursorKey)
	mac.Write(body)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return c, ErrInvalid
	}
	if err := json.Unmarshal(body, &c); err != nil {
		return c, ErrInvalid
	}
	if c.Kind != kind || c.Subject != subject || !bytes.Equal(c.Query, query) {
		return c, ErrInvalid
	}
	return c, nil
}

func times(r *v1.TimeRange) (*time.Time, *time.Time, error) {
	var from, to *time.Time
	if r != nil {
		if r.From != nil {
			if err := r.From.CheckValid(); err != nil {
				return nil, nil, ErrInvalid
			}
			t := r.From.AsTime()
			from = &t
		}
		if r.To != nil {
			if err := r.To.CheckValid(); err != nil {
				return nil, nil, ErrInvalid
			}
			t := r.To.AsTime()
			to = &t
		}
	}
	if from != nil && to != nil && !from.Before(*to) {
		return nil, nil, ErrInvalid
	}
	return from, to, nil
}

func toProto(e Event) *v1.AuditEvent {
	p := &v1.AuditEvent{Seq: e.Seq, PrevHash: e.PrevHash, Hash: e.Hash, At: timestamppb.New(e.At), SubjectId: e.SubjectID, Operation: e.Operation, Hostname: e.Hostname, Action: e.Action, JobId: e.JobID, TaskId: e.TaskID, Decision: e.Decision, MatchedRules: e.MatchedRules, PolicyVersion: e.PolicyVersion, HashInput: e.HashInput, CheckpointSeq: e.CheckpointSeq, CheckpointHash: e.CheckpointHash}
	for _, o := range e.Outputs {
		p.Outputs = append(p.Outputs, &v1.AuditOutputReference{ObjectPath: o.ObjectPath, Sha256: o.SHA256, Stream: v1.OutputStream(o.Stream), StepIndex: o.StepIndex})
	}
	return p
}

func (s *Service) ListAuditEvents(ctx context.Context, r *connect.Request[v1.ListAuditEventsRequest]) (*connect.Response[v1.ListAuditEventsResponse], error) {
	subject, err := s.authorize(ctx, r.Header())
	if err != nil {
		return nil, err
	}
	q := r.Msg.Query
	if q == nil {
		q = &v1.AuditQuery{}
	}
	from, to, err := times(q.Time)
	if err != nil {
		return nil, rpcError(err)
	}
	query, err := proto.MarshalOptions{Deterministic: true}.Marshal(q)
	if err != nil {
		return nil, rpcError(ErrInvalid)
	}
	limit := s.Store.Config.PageSize
	if r.Msg.Page.GetPageSize() != 0 {
		limit = int(r.Msg.Page.PageSize)
	}
	if limit < 1 || limit > s.Store.Config.MaxPageSize {
		return nil, rpcError(ErrLimit)
	}
	c := cursor{Kind: "list", Subject: subject, Query: query, Next: 1}
	if r.Msg.Page.GetPageToken() != "" {
		c, err = s.Store.cursor(r.Msg.Page.PageToken, "list", subject, query)
		if err != nil {
			return nil, rpcError(err)
		}
	} else {
		max, err := maxSeq(ctx, s.Store.Pool)
		if err != nil {
			return nil, rpcError(err)
		}
		if max != nil {
			c.Last = *max
		}
	}
	rows, err := eventsFiltered(ctx, s.Store.Pool, eventFilter{next: c.Next, last: c.Last, from: from, to: to, subject: q.SubjectId, hostname: q.Hostname, action: q.Action, job: q.JobId, oper: q.Operation, limit: limit + 1})
	if err != nil {
		return nil, rpcError(err)
	}
	defer rows.Close()
	out := &v1.ListAuditEventsResponse{Page: &v1.PageResponse{}}
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return nil, rpcError(err)
		}
		if err := checkEvent(e); err != nil {
			return nil, rpcError(ErrUnavailable)
		}
		if len(out.Events) == limit {
			c.Next = e.Seq
			out.Page.NextPageToken, err = s.Store.token(c)
			if err != nil {
				return nil, rpcError(err)
			}
			break
		}
		out.Events = append(out.Events, toProto(e))
		encoded, err := protojson.Marshal(out)
		if err != nil {
			return nil, rpcError(err)
		}
		// Reserve cursor bytes; the token binds all filters and may be large.
		if len(encoded)+len(query)*2+2048 > s.Store.Config.ResponseBytes {
			out.Events = out.Events[:len(out.Events)-1]
			if len(out.Events) == 0 {
				return nil, rpcError(ErrLimit)
			}
			c.Next = e.Seq
			out.Page.NextPageToken, err = s.Store.token(c)
			if err != nil {
				return nil, rpcError(err)
			}
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, rpcError(err)
	}
	return connect.NewResponse(out), nil
}

func (s *Service) ExportAudit(ctx context.Context, r *connect.Request[v1.ExportAuditRequest]) (*connect.Response[v1.ExportAuditResponse], error) {
	subject, err := s.authorize(ctx, r.Header())
	if err != nil {
		return nil, err
	}
	from, to, err := times(r.Msg.Time)
	if err != nil {
		return nil, rpcError(err)
	}
	query, err := proto.MarshalOptions{Deterministic: true}.Marshal(&v1.ExportAuditRequest{Time: r.Msg.Time})
	if err != nil {
		return nil, rpcError(ErrInvalid)
	}
	c := cursor{Kind: "export", Subject: subject, Query: query}
	if r.Msg.PageToken != "" {
		c, err = s.Store.cursor(r.Msg.PageToken, "export", subject, query)
	} else {
		c.Next, c.Last, err = s.Store.Bounds(ctx, from, to)
	}
	if err != nil {
		return nil, rpcError(err)
	}
	if c.Next == 0 {
		return connect.NewResponse(&v1.ExportAuditResponse{}), nil
	}
	p, err := s.Store.ExportPage(ctx, c.Next, c.Last, int(r.Msg.LimitBytes))
	if err != nil {
		return nil, rpcError(err)
	}
	out := &v1.ExportAuditResponse{JsonLines: p.JSONLines, FirstSeq: p.FirstSeq, LastSeq: p.LastSeq, PrecedingHash: p.PrecedingHash, SnapshotLastSeq: p.SnapshotLastSeq}
	if p.LastSeq < c.Last {
		c.Next = p.LastSeq + 1
		out.NextPageToken, err = s.Store.token(c)
		if err != nil {
			return nil, rpcError(err)
		}
	}
	b, err := protojson.Marshal(out)
	if err != nil {
		return nil, rpcError(err)
	}
	if len(b) > s.Store.Config.ResponseBytes {
		return nil, rpcError(ErrLimit)
	}
	return connect.NewResponse(out), nil
}

func (s *Service) VerifyAudit(ctx context.Context, r *connect.Request[v1.VerifyAuditRequest]) (*connect.Response[v1.VerifyAuditResponse], error) {
	if _, err := s.authorize(ctx, r.Header()); err != nil {
		return nil, err
	}
	v, err := s.Store.Verify(ctx, VerifyOptions{From: r.Msg.FromSeq, To: r.Msg.ToSeq, ExpectedPrecedingHash: r.Msg.ExpectedPrecedingHash, ExpectedFinalHash: r.Msg.ExpectedFinalHash})
	if err != nil {
		return nil, rpcError(err)
	}
	return connect.NewResponse(&v1.VerifyAuditResponse{Valid: v.Valid, CheckedCount: v.CheckedCount, FirstInvalidSeq: v.FirstInvalidSeq, Reason: v.Reason, ActualPrecedingHash: v.ActualPrecedingHash, ActualFinalHash: v.ActualFinalHash, ExternallyAnchored: v.ExternallyAnchored}), nil
}

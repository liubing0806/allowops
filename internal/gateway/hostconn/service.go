package hostconn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/store/db"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type identityKey struct{}
type writeDeadlineKey struct{}

func WithWriteDeadline(ctx context.Context, set func(time.Time) error) context.Context {
	return context.WithValue(ctx, writeDeadlineKey{}, set)
}

func (s *Service) send(ctx context.Context, send func() error) error {
	if set, ok := ctx.Value(writeDeadlineKey{}).(func(time.Time) error); ok {
		deadline := time.Now().Add(s.Config.HeartbeatTimeout)
		if expires, ok := ctx.Deadline(); ok && expires.Before(deadline) {
			deadline = expires
		}
		if err := set(deadline); err != nil {
			return err
		}
		defer set(time.Time{})
	}
	return send()
}

type Identity struct {
	HostID, Serial string
	ExpiresAt      time.Time
}

func WithIdentity(ctx context.Context, cert *x509.Certificate) (context.Context, error) {
	if len(cert.URIs) != 1 || cert.URIs[0].Scheme != "spiffe" || cert.URIs[0].Host != "allowops" || cert.URIs[0].Path != "/hosts/"+cert.Subject.CommonName || cert.Subject.CommonName == "" {
		return nil, store.ErrCredential
	}
	return context.WithValue(ctx, identityKey{}, Identity{cert.Subject.CommonName, cert.SerialNumber.Text(16), cert.NotAfter}), nil
}

type Event struct {
	HostID, ConnectionID string
	Message              *v1.ConnectRequest
}

// Hooks execute on the connection owner. Output is delivered only to OnMessage,
// never through gateway_messages. P6 must persist it before returning.
type Hooks struct {
	OnMessage    func(context.Context, Event) error
	OnDisconnect func(Event)
	Drain        func(context.Context) error
}

type outbound struct {
	message *v1.ConnectResponse
	receipt chan error
	mailbox string
}
type connection struct {
	identity    Identity
	id          string
	ctx         context.Context
	cancel      context.CancelFunc
	queue       chan outbound
	catalogWake chan struct{}
	bytes       atomic.Int64
	messages    atomic.Int64
	lastSeen    atomic.Pointer[time.Time] // Retain time.Now's monotonic clock for heartbeat elapsed time.
	maxInflight int
	mu          sync.Mutex
	pending     map[string][]string // task ID -> transient mailbox IDs
	report      *v1.CatalogLoadReport
	reportPage  uint32
	loaded      map[string]*v1.CatalogLoadReport
}

type Service struct {
	Store          *store.Store
	CA             *CA
	Config         Config
	InstanceID     string
	Hooks          Hooks
	draining       atomic.Bool
	listenerFailed atomic.Bool
	mu             sync.Mutex
	connections    map[string]*connection
	pulls          map[string]bool
	ctx            context.Context
	cancel         context.CancelFunc
	done           chan struct{}
}

func New(s *store.Store, ca *CA, config Config, hooks Hooks) (*Service, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &Service{Store: s, CA: ca, Config: config, InstanceID: rand.Text(), Hooks: hooks, connections: map[string]*connection{}, pulls: map[string]bool{}, done: make(chan struct{})}, nil
}

// Start establishes LISTEN before accepting connections or routing messages.
// The dedicated listener must not consume capacity from the query pool.
func (s *Service) Start(ctx context.Context) error {
	if err := s.Store.CheckSchema(ctx); err != nil {
		return err
	}
	if err := s.Store.Queries.RegisterInstance(ctx, s.InstanceID); err != nil {
		return err
	}
	if _, err := s.Store.Pool.Exec(ctx, "UPDATE gateway_instances SET version=$2 WHERE instance_id=$1", s.InstanceID, s.Config.Version); err != nil {
		return err
	}
	run, cancel := context.WithCancel(ctx)
	l, err := pgx.ConnectConfig(run, s.Store.Pool.Config().ConnConfig.Copy())
	if err != nil {
		cancel()
		return err
	}
	if _, err := l.Exec(run, "LISTEN "+store.NotificationChannel); err != nil {
		l.Close(run)
		cancel()
		return err
	}
	s.ctx, s.cancel = run, cancel
	go func() {
		defer close(s.done)
		defer func() {
			closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			l.Close(closeCtx)
		}()
		defer s.disconnectAll()
		for {
			waitCtx, cancel := context.WithTimeout(s.ctx, time.Second)
			n, err := l.WaitForNotification(waitCtx)
			cancel()
			if s.ctx.Err() != nil {
				return
			}
			if err != nil && !errors.Is(err, context.DeadlineExceeded) {
				s.listenerFailed.Store(true)
				s.draining.Store(true)
				return
			}
			if n != nil {
				s.notification(n.Payload)
			}
		}
	}()
	go s.maintenance()
	return nil
}

// ListenerFailed reports a fatal failure of the dedicated routing listener.
// Restart remains necessary to restore routing.
func (s *Service) ListenerFailed() bool { return s.listenerFailed.Load() }

func (s *Service) authenticate(ctx context.Context) (Identity, error) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	if !ok || time.Now().After(id.ExpiresAt) {
		return Identity{}, rpcError(store.ErrCredential)
	}
	if err := s.Store.CheckIdentity(ctx, id.HostID, id.Serial); err != nil {
		return Identity{}, rpcError(err)
	}
	return id, nil
}

func rpcError(err error) error {
	code, message := connect.CodeInternal, "gateway operation failed"
	switch {
	case errors.Is(err, store.ErrCredential):
		code, message = connect.CodeUnauthenticated, "invalid credential"
	case errors.Is(err, store.ErrHostname):
		code, message = connect.CodeAlreadyExists, "hostname already exists"
	case errors.Is(err, store.ErrOffline):
		code, message = connect.CodeUnavailable, "host offline"
	case errors.Is(err, store.ErrCapacity):
		code, message = connect.CodeResourceExhausted, "gateway capacity exceeded"
	case errors.Is(err, pgx.ErrNoRows):
		code, message = connect.CodeNotFound, "resource not found"
	}
	return rpcFailure(code, errors.New(message))
}

func rpcFailure(code connect.Code, err error) error {
	reasons := map[connect.Code]string{connect.CodeUnauthenticated: "INVALID_CREDENTIAL", connect.CodeAlreadyExists: "HOSTNAME_EXISTS", connect.CodeResourceExhausted: "LIMIT_EXCEEDED", connect.CodeInvalidArgument: "INVALID_PARAMETERS", connect.CodeUnimplemented: "AGENT_VERSION_UNSUPPORTED", connect.CodeUnavailable: "GATEWAY_DRAINING", connect.CodeDeadlineExceeded: "RPC_TIMEOUT", connect.CodeNotFound: "RESOURCE_NOT_FOUND", connect.CodeDataLoss: "CATALOG_HASH_MISMATCH", connect.CodeInternal: "INTERNAL_ERROR"}
	e := connect.NewError(code, err)
	detail := &v1.ErrorDetail{Reason: reasons[code]}
	if code == connect.CodeInternal {
		detail.RequestId = rand.Text()
	}
	if d, err := connect.NewErrorDetail(detail); err == nil {
		e.AddDetail(d)
	}
	return e
}

func hostCertificate(id string, c *IssuedCertificate) *v1.HostCertificate {
	return &v1.HostCertificate{HostId: id, CertificateChainPem: c.PEM, ExpiresAt: timestamppb.New(c.ExpiresAt), RenewAfter: timestamppb.New(c.RenewAfter)}
}

func (s *Service) CreateJoinToken(ctx context.Context, maxUses int64, ttl time.Duration) (string, error) {
	if ttl == 0 {
		ttl = s.Config.MultiJoinTTL
		if maxUses == 1 {
			ttl = s.Config.SingleJoinTTL
		}
	}
	return s.Store.CreateJoinToken(ctx, maxUses, ttl)
}

func (s *Service) Join(ctx context.Context, request *connect.Request[v1.JoinRequest]) (*connect.Response[v1.JoinResponse], error) {
	if s.draining.Load() {
		return nil, rpcFailure(connect.CodeUnavailable, errors.New("gateway draining"))
	}
	r := request.Msg
	if r.Hostname == "" || len(r.Hostname) > 253 || !utf8.ValidString(r.Hostname) || strings.ContainsAny(r.Hostname, "\x00\r\n\t /\\") || len(r.JoinToken) > 1024 {
		return nil, rpcFailure(connect.CodeInvalidArgument, errors.New("invalid hostname or token format"))
	}
	if _, err := ParseCSR(r.CsrPem); err != nil {
		return nil, rpcFailure(connect.CodeInvalidArgument, errors.New("invalid CSR"))
	}
	var issued *IssuedCertificate
	id, err := s.Store.Register(ctx, r.JoinToken, r.Hostname, func(id string) (string, time.Time, error) {
		var err error
		issued, err = s.CA.Issue(id, r.CsrPem, s.Config.CertificateTTL)
		if err != nil {
			return "", time.Time{}, err
		}
		return issued.Serial, issued.ExpiresAt, nil
	})
	if err != nil {
		return nil, rpcError(err)
	}
	return connect.NewResponse(&v1.JoinResponse{Certificate: hostCertificate(id, issued)}), nil
}

func (s *Service) RenewCertificate(ctx context.Context, r *connect.Request[v1.RenewCertificateRequest]) (*connect.Response[v1.RenewCertificateResponse], error) {
	id, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := ParseCSR(r.Msg.CsrPem); err != nil {
		return nil, rpcFailure(connect.CodeInvalidArgument, errors.New("invalid CSR"))
	}
	var issued *IssuedCertificate
	err = s.Store.Renew(ctx, id.HostID, id.Serial, func() (string, time.Time, error) {
		var err error
		issued, err = s.CA.Issue(id.HostID, r.Msg.CsrPem, s.Config.CertificateTTL)
		if err != nil {
			return "", time.Time{}, err
		}
		return issued.Serial, issued.ExpiresAt, nil
	})
	if err != nil {
		return nil, rpcError(err)
	}
	return connect.NewResponse(&v1.RenewCertificateResponse{Certificate: hostCertificate(id.HostID, issued)}), nil
}

func (s *Service) PullCatalog(ctx context.Context, r *connect.Request[v1.PullCatalogRequest], stream *connect.ServerStream[v1.PullCatalogResponse]) error {
	id, err := s.authenticate(ctx)
	if err != nil {
		return err
	}
	ref := r.Msg.Catalog
	if ref == nil || ref.CatalogId == "" || ref.Version == 0 || ref.Version > 1<<63-1 {
		return rpcFailure(connect.CodeInvalidArgument, errors.New("concrete catalog version required"))
	}
	s.mu.Lock()
	if s.pulls[id.HostID] {
		s.mu.Unlock()
		return rpcFailure(connect.CodeResourceExhausted, errors.New("catalog pull already in progress"))
	}
	s.pulls[id.HostID] = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.pulls, id.HostID); s.mu.Unlock() }()
	v, err := s.Store.Queries.GetCatalog(ctx, db.GetCatalogParams{CatalogID: ref.CatalogId, Version: int64(ref.Version)})
	if err != nil {
		return rpcError(err)
	}
	digest := sha256.Sum256(v.Dsse)
	if len(v.Dsse) > s.Config.EnvelopeBytes || string(digest[:]) != string(v.Digest) {
		return rpcFailure(connect.CodeDataLoss, errors.New("catalog integrity check failed"))
	}
	for offset := 0; offset < len(v.Dsse); {
		if _, err := s.authenticate(ctx); err != nil {
			return err
		}
		end := min(offset+s.Config.ChunkBytes, len(v.Dsse))
		if err := s.send(ctx, func() error {
			return stream.Send(&v1.PullCatalogResponse{Catalog: ref, Offset: uint64(offset), Data: v.Dsse[offset:end], Eof: end == len(v.Dsse), EnvelopeSha256: v.Digest})
		}); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

func (s *Service) validateLabels(labels map[string]string) error {
	if len(labels) > s.Config.ReportedLabelCount {
		return fmt.Errorf("too many reported labels")
	}
	for k, v := range labels {
		if k == "" || len(k) > s.Config.ReportedLabelKeyBytes || len(v) > s.Config.ReportedLabelValueBytes || !utf8.ValidString(k) || !utf8.ValidString(v) {
			return fmt.Errorf("invalid reported label")
		}
	}
	return nil
}

func (s *Service) Connect(ctx context.Context, stream *connect.BidiStream[v1.ConnectRequest, v1.ConnectResponse]) error {
	id, err := s.authenticate(ctx)
	if err != nil {
		return err
	}
	if s.draining.Load() {
		return rpcFailure(connect.CodeUnavailable, errors.New("gateway draining"))
	}
	cctx, cancel := context.WithDeadline(ctx, id.ExpiresAt)
	defer cancel()
	type received struct {
		message *v1.ConnectRequest
		err     error
	}
	incoming := make(chan received, 1)
	go func() {
		for {
			m, e := stream.Receive()
			select {
			case incoming <- received{m, e}:
			case <-cctx.Done():
				return
			}
			if e != nil {
				return
			}
		}
	}()
	timer := time.NewTimer(s.Config.HeartbeatTimeout)
	defer timer.Stop()
	var first received
	select {
	case first = <-incoming:
	case <-timer.C:
		return rpcFailure(connect.CodeDeadlineExceeded, errors.New("agent hello timeout"))
	case <-ctx.Done():
		return ctx.Err()
	}
	if first.err != nil {
		return first.err
	}
	h := first.message.GetHello()
	if h == nil || h.MaxConcurrentTasks == 0 {
		return rpcFailure(connect.CodeInvalidArgument, errors.New("first message must be AgentHello with positive capacity"))
	}
	if err := CheckVersion(s.Config.Version, h.AgentVersion); err != nil {
		return rpcFailure(connect.CodeUnimplemented, errors.New("agent version unsupported"))
	}
	if err := s.validateLabels(h.ReportedLabels); err != nil {
		return rpcFailure(connect.CodeInvalidArgument, err)
	}
	c := &connection{identity: id, id: rand.Text(), ctx: cctx, cancel: cancel, queue: make(chan outbound, s.Config.QueueMessages), catalogWake: make(chan struct{}, 1), maxInflight: min(s.Config.MaxInflight, int(h.MaxConcurrentTasks)), pending: map[string][]string{}, loaded: map[string]*v1.CatalogLoadReport{}}
	connectedAt := time.Now()
	c.lastSeen.Store(&connectedAt)
	// Serialize replacement with sends using the host row lock. Register in memory
	// before commit so a committed NOTIFY always has a local destination.
	tx, err := s.Store.Pool.Begin(ctx)
	if err != nil {
		return rpcError(err)
	}
	defer tx.Rollback(ctx)
	labels, _ := json.Marshal(h.ReportedLabels)
	capabilities, _ := proto.Marshal(h.Capabilities)
	var ok string
	err = tx.QueryRow(ctx, "UPDATE hosts SET instance_id=$2,connection_id=$3,reported_labels=$4,agent_version=$5,last_seen=now(),capabilities=$7 WHERE host_id=$1 AND certificate_status='active' AND certificate_serial=$6 RETURNING host_id", id.HostID, s.InstanceID, c.id, labels, h.AgentVersion, id.Serial, capabilities).Scan(&ok)
	if err != nil {
		return rpcError(err)
	}
	s.mu.Lock()
	old := s.connections[id.HostID]
	s.connections[id.HostID] = c
	s.mu.Unlock()
	if old != nil {
		old.cancel()
	}
	defer s.disconnected(c)
	if err := store.Notify(ctx, tx, "host:"+id.HostID); err != nil {
		return rpcError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return rpcError(err)
	}
	if err := s.send(cctx, func() error {
		return stream.Send(&v1.ConnectResponse{Message: &v1.ConnectResponse_Hello{Hello: &v1.GatewayHello{GatewayVersion: s.Config.Version, ConnectionId: c.id, ServerTime: timestamppb.Now(), Limits: &v1.ConnectionLimits{HeartbeatInterval: durationpb.New(s.Config.HeartbeatInterval), HeartbeatTimeout: durationpb.New(s.Config.HeartbeatTimeout), MaxMessageBytes: uint32(s.Config.MessageBytes), MaxChunkBytes: uint32(s.Config.ChunkBytes), MaxInflightTasks: uint32(c.maxInflight)}}}})
	}); err != nil {
		return err
	}
	go s.catalogWorker(c)
	s.catalogs(c)
	ticker := time.NewTicker(min(s.Config.HeartbeatInterval, time.Second))
	defer ticker.Stop()
	tokens, lastRefill := float64(s.Config.ReceiveBurst), time.Now()
	var sequence uint64
	for {
		select {
		case <-cctx.Done():
			if !time.Now().Before(id.ExpiresAt) {
				return rpcError(store.ErrCredential)
			}
			return rpcFailure(connect.CodeUnavailable, errors.New("connection replaced or gateway draining"))
		case <-ticker.C:
			if time.Since(*c.lastSeen.Load()) > s.Config.HeartbeatTimeout {
				return rpcFailure(connect.CodeDeadlineExceeded, errors.New("heartbeat timeout"))
			}
			if err := s.Store.CheckHostActive(cctx, id.HostID); err != nil {
				if !time.Now().Before(id.ExpiresAt) {
					return rpcError(store.ErrCredential)
				}
				return rpcError(err)
			}
		case item := <-c.queue:
			err := s.write(c, stream, item)
			c.bytes.Add(-int64(proto.Size(item.message)))
			c.messages.Add(-1)
			if item.receipt != nil {
				item.receipt <- err
			}
			if err != nil {
				return rpcError(err)
			}
		case r := <-incoming:
			if r.err != nil {
				if errors.Is(r.err, io.EOF) {
					return nil
				}
				return r.err
			}
			now := time.Now()
			tokens = min(float64(s.Config.ReceiveBurst), tokens+now.Sub(lastRefill).Seconds()*float64(s.Config.ReceiveRate))
			lastRefill = now
			if tokens < 1 {
				return rpcFailure(connect.CodeResourceExhausted, errors.New("receive rate exceeded"))
			}
			tokens--
			if output := r.message.GetOutput(); output != nil && len(output.Data) > s.Config.ChunkBytes {
				return rpcFailure(connect.CodeResourceExhausted, errors.New("output chunk too large"))
			}
			if heartbeat := r.message.GetHeartbeat(); heartbeat != nil {
				if heartbeat.Sequence <= sequence {
					return rpcFailure(connect.CodeInvalidArgument, errors.New("heartbeat sequence must increase"))
				}
				sequence = heartbeat.Sequence
				c.lastSeen.Store(&now)
				if err := s.send(cctx, func() error {
					return stream.Send(&v1.ConnectResponse{Message: &v1.ConnectResponse_Heartbeat{Heartbeat: &v1.GatewayHeartbeat{Sequence: sequence, ServerTime: timestamppb.Now()}}})
				}); err != nil {
					return err
				}
				continue
			}
			if r.message.GetMessage() == nil || r.message.GetHello() != nil {
				return rpcFailure(connect.CodeInvalidArgument, errors.New("invalid connection message"))
			}
			if load := r.message.GetCatalogLoad(); load != nil {
				if err := s.catalogReport(c, load); err != nil {
					return err
				}
				if !load.FinalPage {
					continue
				}
				r.message = &v1.ConnectRequest{Message: &v1.ConnectRequest_CatalogLoad{CatalogLoad: s.CatalogReport(id.HostID, load.Catalog.CatalogId)}}
			}
			if s.Hooks.OnMessage != nil {
				if err := s.Hooks.OnMessage(cctx, Event{id.HostID, c.id, r.message}); err != nil {
					return err
				}
			}
			if completed := r.message.GetTaskCompleted(); completed != nil {
				if err := s.complete(c, completed); err != nil {
					return rpcError(err)
				}
			}
		}
	}
}

func (s *Service) enqueue(c *connection, item outbound) error {
	n := int64(proto.Size(item.message))
	if c.messages.Add(1) > int64(s.Config.QueueMessages) {
		c.messages.Add(-1)
		return store.ErrCapacity
	}
	if n > int64(s.Config.MessageBytes) || c.bytes.Add(n) > int64(s.Config.QueueBytes) {
		c.messages.Add(-1)
		if n <= int64(s.Config.MessageBytes) {
			c.bytes.Add(-n)
		}
		return store.ErrCapacity
	}
	select {
	case c.queue <- item:
		return nil
	default:
		c.bytes.Add(-n)
		c.messages.Add(-1)
		return store.ErrCapacity
	}
}

func (s *Service) snapshot() []*connection {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*connection, 0, len(s.connections))
	for _, c := range s.connections {
		out = append(out, c)
	}
	return out
}
func (s *Service) disconnectAll() {
	for _, c := range s.snapshot() {
		c.cancel()
	}
}

func (s *Service) disconnected(c *connection) {
	c.cancel()
	s.mu.Lock()
	if s.connections[c.identity.HostID] == c {
		delete(s.connections, c.identity.HostID)
	}
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.Store.Queries.DisconnectHost(ctx, db.DisconnectHostParams{HostID: c.identity.HostID, ConnectionID: pgtype.Text{String: c.id, Valid: true}, LastSeen: store.Timestamp(*c.lastSeen.Load())})
	_ = s.failConnection(ctx, c.id)
	if s.Hooks.OnDisconnect != nil {
		s.Hooks.OnDisconnect(Event{HostID: c.identity.HostID, ConnectionID: c.id})
	}
}

func (s *Service) catalogs(c *connection) {
	select {
	case c.catalogWake <- struct{}{}:
	default:
	}
}

func (s *Service) catalogWorker(c *connection) {
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.catalogWake:
			versions, err := s.Store.Queries.CurrentCatalogs(c.ctx)
			if err != nil {
				c.cancel()
				return
			}
			for _, v := range versions {
				m := &v1.ConnectResponse{Message: &v1.ConnectResponse_CatalogAvailable{CatalogAvailable: &v1.CatalogAvailable{Catalog: &v1.CatalogRef{CatalogId: v.CatalogID, Version: uint64(v.Version)}, EnvelopeSha256: v.Digest, EnvelopeSizeBytes: uint64(v.EnvelopeSizeBytes)}}}
				for {
					if err := s.enqueue(c, outbound{message: m}); err == nil {
						break
					}
					select {
					case <-c.ctx.Done():
						return
					case <-time.After(10 * time.Millisecond):
					}
				}
			}
		}
	}
}

func (s *Service) catalogReport(c *connection, r *v1.CatalogLoadReport) error {
	invalid := func() error {
		return rpcFailure(connect.CodeInvalidArgument, errors.New("invalid catalog load report"))
	}
	if r.Catalog == nil || r.Catalog.Version == 0 || r.Catalog.Version > 1<<63-1 || r.ReportId == "" || len(r.UnsupportedActions) > 100 {
		return invalid()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.PageIndex == 0 {
		if c.report != nil {
			return invalid()
		}
		_, err := s.Store.Queries.GetCatalog(c.ctx, db.GetCatalogParams{CatalogID: r.Catalog.CatalogId, Version: int64(r.Catalog.Version)})
		if err != nil {
			return invalid()
		}
		c.report = proto.Clone(r).(*v1.CatalogLoadReport)
		c.reportPage = 0
	} else {
		p := c.report
		if p == nil || r.PageIndex != c.reportPage+1 || r.ReportId != p.ReportId || !proto.Equal(r.Catalog, p.Catalog) || r.Loaded != p.Loaded || r.Reason != p.Reason {
			return invalid()
		}
		p.UnsupportedActions = append(p.UnsupportedActions, r.UnsupportedActions...)
		c.reportPage = r.PageIndex
	}
	if proto.Size(c.report) > s.Config.MessageBytes {
		return rpcFailure(connect.CodeResourceExhausted, errors.New("catalog report too large"))
	}
	if r.FinalPage {
		c.report.FinalPage = true
		raw, err := proto.Marshal(c.report)
		if err != nil {
			return err
		}
		// Only complete validated reports become visible; fence replaced connections.
		// Snapshot persistence must not introduce new connection failures.
		_, _ = s.Store.Pool.Exec(c.ctx, `INSERT INTO host_catalog_reports(host_id,catalog_id,version,loaded,report)
 SELECT host_id,$2,$3,$4,$5 FROM hosts WHERE host_id=$1 AND connection_id=$6 AND certificate_status='active'
 ON CONFLICT(host_id,catalog_id) DO UPDATE SET version=EXCLUDED.version,loaded=EXCLUDED.loaded,report=EXCLUDED.report`, c.identity.HostID, r.Catalog.CatalogId, int64(r.Catalog.Version), r.Loaded, raw, c.id)
		c.loaded[r.Catalog.CatalogId] = c.report
		c.report = nil
	}
	return nil
}

func (s *Service) CatalogReport(hostID, catalogID string) *v1.CatalogLoadReport {
	s.mu.Lock()
	c := s.connections[hostID]
	s.mu.Unlock()
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.loaded[catalogID]
	if r == nil {
		return nil
	}
	return proto.Clone(r).(*v1.CatalogLoadReport)
}

func (s *Service) maintenance() {
	flush := time.NewTicker(s.Config.FlushInterval)
	cleanup := time.NewTicker(s.Config.CleanupInterval)
	defer flush.Stop()
	defer cleanup.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-flush.C:
			for _, c := range s.snapshot() {
				_ = s.Store.Queries.TouchConnection(s.ctx, db.TouchConnectionParams{HostID: c.identity.HostID, ConnectionID: pgtype.Text{String: c.id, Valid: true}, LastSeen: store.Timestamp(*c.lastSeen.Load())})
			}
			_, _ = s.Store.Pool.Exec(s.ctx, "UPDATE gateway_instances SET last_seen=now() WHERE instance_id=$1", s.InstanceID)
		case <-cleanup.C:
			_ = s.Store.Queries.DeleteExpiredMessages(s.ctx)
		}
	}
}

// Drain rejects new dispatch immediately. P6's optional hook waits for running
// work. Each host gets a cryptographically random delay within the configured range.
func (s *Service) Drain(ctx context.Context) error {
	s.draining.Store(true)
	_, _ = s.Store.Pool.Exec(ctx, "UPDATE gateway_instances SET draining=true WHERE instance_id=$1", s.InstanceID)
	if s.Hooks.Drain != nil {
		if err := s.Hooks.Drain(ctx); err != nil {
			return err
		}
	}
	for _, c := range s.snapshot() {
		rangeNS := int64(s.Config.ReconnectMax - s.Config.ReconnectMin)
		n, _ := rand.Int(rand.Reader, big.NewInt(rangeNS+1))
		delay := s.Config.ReconnectMin + time.Duration(n.Int64())
		receipt := make(chan error, 1)
		msg := &v1.ConnectResponse{Message: &v1.ConnectResponse_Reconnect{Reconnect: &v1.Reconnect{Reason: "gateway draining", CloseAt: timestamppb.New(time.Now().Add(s.Config.ShutdownGrace)), RetryAfterMin: durationpb.New(delay), RetryAfterMax: durationpb.New(delay)}}}
		if err := s.enqueue(c, outbound{message: msg, receipt: receipt}); err != nil {
			c.cancel()
			continue
		}
		select {
		case <-receipt:
			c.cancel()
		case <-c.ctx.Done():
		case <-ctx.Done():
			c.cancel()
			return ctx.Err()
		}
	}
	return nil
}

func (s *Service) Close() {
	if s.cancel != nil {
		s.cancel()
		<-s.done
	}
}

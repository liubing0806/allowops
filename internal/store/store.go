package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/liubing0806/allowops/internal/store/db"
	"github.com/pressly/goose/v3"
)

const SchemaVersion int64 = 7
const NotificationChannel = "allowops_gateway"

//go:embed migrations/*.sql
var migrations embed.FS

var ErrCredential = errors.New("invalid credential")
var ErrHostname = errors.New("hostname already exists")
var ErrOffline = errors.New("host offline")
var ErrRollback = errors.New("catalog version must strictly increase")
var ErrActionConflict = errors.New("action name conflicts with another catalog")
var ErrCapacity = errors.New("gateway message capacity exceeded")

type Store struct {
	Pool    *pgxpool.Pool
	Queries *db.Queries
}

func Open(ctx context.Context, dsn string) (*Store, error) {
	p, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("configure PostgreSQL")
	}
	if err := p.Ping(ctx); err != nil {
		p.Close()
		return nil, fmt.Errorf("connect PostgreSQL")
	}
	return &Store{Pool: p, Queries: db.New(p)}, nil
}

func (s *Store) Close() { s.Pool.Close() }

func migrationProvider(dsn string) (*goose.Provider, func(), error) {
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("configure migration database")
	}
	conn := stdlib.OpenDB(*config)
	folder, err := fs.Sub(migrations, "migrations")
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	p, err := goose.NewProvider(goose.DialectPostgres, conn, folder)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return p, func() { conn.Close() }, nil
}

func Migrate(ctx context.Context, dsn string) error {
	p, closeDB, err := migrationProvider(dsn)
	if err != nil {
		return err
	}
	defer closeDB()
	_, err = p.Up(ctx)
	if err != nil {
		return fmt.Errorf("PostgreSQL migration failed")
	}
	return nil
}

func (s *Store) CheckSchema(ctx context.Context) error {
	// A readonly check must not initialize goose's version table.
	var v int64
	err := s.Pool.QueryRow(ctx, "SELECT COALESCE(max(version_id),0) FROM goose_db_version WHERE is_applied").Scan(&v)
	if err != nil {
		return fmt.Errorf("schema unavailable; run allowops-gateway migrate")
	}
	if v != SchemaVersion {
		return fmt.Errorf("schema version %d, require %d", v, SchemaVersion)
	}
	return nil
}

func Timestamp(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }

func (s *Store) CreateJoinToken(ctx context.Context, maxUses int64, ttl time.Duration) (string, error) {
	if maxUses <= 0 || ttl <= 0 {
		return "", fmt.Errorf("positive max_uses and TTL required")
	}
	secret := rand.Text()
	hash := sha256.Sum256([]byte(secret))
	_, err := s.Pool.Exec(ctx, "INSERT INTO join_tokens(token_id,token_hash,max_uses,expires_at) VALUES ($1,$2,$3,$4)", rand.Text(), hash[:], maxUses, time.Now().Add(ttl))
	if err != nil {
		return "", err
	}
	return secret, nil
}

func (s *Store) RevokeJoinToken(ctx context.Context, secret string) error {
	h := sha256.Sum256([]byte(secret))
	_, err := s.Pool.Exec(ctx, "UPDATE join_tokens SET revoked=true,revoked_at=CASE WHEN revoked THEN revoked_at ELSE now() END WHERE token_hash=$1", h[:])
	return err
}

// Register rolls back consumption when hostname insertion fails. The signing
// callback runs inside the transaction so signing failures cannot consume tokens.
func (s *Store) Register(ctx context.Context, secret, hostname string, sign func(string) (string, time.Time, error)) (string, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	h := sha256.Sum256([]byte(secret))
	q := s.Queries.WithTx(tx)
	if _, err := q.ConsumeToken(ctx, h[:]); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrCredential
		}
		return "", err
	}
	id := rand.Text()
	serial, expires, err := sign(id)
	if err != nil {
		return "", err
	}
	if err := q.InsertHost(ctx, db.InsertHostParams{HostID: id, Hostname: hostname, CertificateSerial: serial, CertificateExpiresAt: Timestamp(expires)}); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return "", ErrHostname
		}
		return "", err
	}
	return id, tx.Commit(ctx)
}

func (s *Store) CheckIdentity(ctx context.Context, id, serial string) error {
	var valid bool
	err := s.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM hosts WHERE host_id=$1 AND certificate_serial=$2 AND certificate_status='active' AND certificate_expires_at>now())", id, serial).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrCredential
	}
	return nil
}

// CheckHostActive is only for an already authenticated Connect stream. An
// existing stream keeps its original certificate until expiry; deletion still
// revokes it (protocol G18).
func (s *Store) CheckHostActive(ctx context.Context, id string) error {
	var active bool
	if err := s.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM hosts WHERE host_id=$1 AND certificate_status='active')", id).Scan(&active); err != nil {
		return err
	}
	if !active {
		return ErrCredential
	}
	return nil
}

func (s *Store) Renew(ctx context.Context, id, oldSerial string, sign func() (string, time.Time, error)) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var serial string
	err = tx.QueryRow(ctx, "SELECT certificate_serial FROM hosts WHERE host_id=$1 AND certificate_status='active' AND certificate_expires_at>now() FOR UPDATE", id).Scan(&serial)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && serial != oldSerial) {
		return ErrCredential
	}
	if err != nil {
		return err
	}
	newSerial, expires, err := sign()
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE hosts SET certificate_serial=$2,certificate_expires_at=$3 WHERE host_id=$1", id, newSerial, expires); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func Notify(ctx context.Context, tx pgx.Tx, payload string) error {
	_, err := tx.Exec(ctx, "SELECT pg_notify($1,$2)", NotificationChannel, payload)
	return err
}

func (s *Store) DeleteHost(ctx context.Context, id string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := DeleteHostTx(ctx, tx, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DeleteHostTx applies the gateway's host deletion and notification within the caller transaction.
func DeleteHostTx(ctx context.Context, tx pgx.Tx, id string) error {
	if _, err := tx.Exec(ctx, "UPDATE hosts SET certificate_status='deleted',instance_id=NULL,connection_id=NULL WHERE host_id=$1", id); err != nil {
		return err
	}
	if err := Notify(ctx, tx, "host:"+id); err != nil {
		return err
	}
	return nil
}

// CheckActionNames is the single replaceable check that action names are
// globally unique across catalogs (decisions A11). Publication serializes this
// check and the version check with the insert under one lock.
func CheckActionNames(incomingID string, names []string, current []db.CurrentCatalogsRow) error {
	seen := map[string]bool{}
	for _, v := range current {
		if v.CatalogID != incomingID {
			for _, name := range v.ActionNames {
				seen[name] = true
			}
		}
	}
	for _, name := range names {
		if seen[name] {
			return ErrActionConflict
		}
	}
	return nil
}

func (s *Store) Publish(ctx context.Context, v db.InsertCatalogParams) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := s.PublishTx(ctx, tx, v); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// PublishTx shares the version, global-name and notification checks between the
// host-facing and management-API publishing paths (design P4, P4B).
func (s *Store) PublishTx(ctx context.Context, tx pgx.Tx, v db.InsertCatalogParams) error {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(418001)"); err != nil {
		return err
	}
	q := s.Queries.WithTx(tx)
	current, err := q.CurrentCatalogs(ctx)
	if err != nil {
		return err
	}
	for _, c := range current {
		if c.CatalogID == v.CatalogID && v.Version <= c.Version {
			return ErrRollback
		}
	}
	if err := CheckActionNames(v.CatalogID, v.ActionNames, current); err != nil {
		return err
	}
	if err := q.InsertCatalog(ctx, v); err != nil {
		return err
	}
	if err := Notify(ctx, tx, "catalog:"); err != nil {
		return err
	}
	return nil
}

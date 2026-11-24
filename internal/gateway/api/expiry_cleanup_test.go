package api

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/liubing0806/allowops/internal/store/db"
)

type expiryCleanupObserver struct {
	db.DBTX
	swept    chan error
	canceled chan struct{}
	release  chan struct{}
}

func (o expiryCleanupObserver) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tag, err := o.DBTX.Exec(ctx, sql, args...)
	if strings.Contains(sql, "DELETE FROM identity_sessions") {
		o.swept <- err
		<-ctx.Done()
		close(o.canceled)
		<-o.release
		return tag, ctx.Err()
	}
	return tag, err
}

func TestExpiryCleanupDeletesOneBatchAndStopsWithService(t *testing.T) {
	f := newFixture(t)
	f.service.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := f.db.Pool.Exec(ctx, `
		INSERT INTO policy_tests(test_id,actor_id,base_version,candidate,candidate_hash,snapshot_hash,environment,test,changes,expires_at)
		SELECT 'p-'||n,'seed',1,'{}',decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'),'{}','{}','{}',
			CASE WHEN n=1002 THEN now()+interval '1 hour' ELSE now()-n*interval '1 second' END
		FROM generate_series(1,1002) n;
		INSERT INTO cli_login_codes(code_hash,user_id,challenge,expires_at)
		SELECT decode(repeat(hash_byte,32),'hex'), user_id, 'seed', now()+expiry
		FROM (VALUES ('01',interval '-1 hour'), ('02',interval '1 hour')) c(hash_byte,expiry)
		CROSS JOIN (SELECT user_id FROM console_users WHERE provider_subject='admin') u;
		INSERT INTO oidc_transactions(state_hash,provider_id,client,nonce,provider_verifier,expires_at)
		VALUES (decode(repeat('01',32),'hex'),'seed','cli','nonce','verifier',now()-interval '1 hour'),
		       (decode(repeat('02',32),'hex'),'seed','cli','nonce','verifier',now()+interval '1 hour');
		INSERT INTO identity_sessions(session_id,user_id,token_hash,client,created_at,expires_at,revoked_at)
		SELECT id,user_id,decode(repeat(hash_byte,32),'hex'),'cli',now()-interval '60 days',
			now()+expiry,CASE WHEN revoked THEN now()-interval '2 days' END
		FROM (VALUES ('old','01',interval '-31 days',false), ('recent','02',interval '-29 days',false),
		             ('revoked','03',interval '-1 day',true), ('active','04',interval '1 day',false)) s(id,hash_byte,expiry,revoked)
		CROSS JOIN (SELECT user_id FROM console_users WHERE provider_subject='admin') u
	`)
	if err != nil {
		t.Fatal(err)
	}
	observer := expiryCleanupObserver{
		DBTX: f.db.Pool, swept: make(chan error, 1), canceled: make(chan struct{}), release: make(chan struct{}),
	}
	release := sync.OnceFunc(func() { close(observer.release) })
	defer release()
	f.db.Queries = db.New(observer)
	if err := f.service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-observer.swept:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("API maintenance did not sweep expiry records after startup")
	}
	var policies, sessions []string
	var expiredCodes, liveCodes, expiredTransactions, liveTransactions int
	err = f.db.Pool.QueryRow(ctx, `
		SELECT ARRAY(SELECT test_id FROM policy_tests ORDER BY test_id),
		       ARRAY(SELECT session_id FROM identity_sessions
		             WHERE session_id IN ('old','recent','revoked','active') ORDER BY session_id),
		       (SELECT count(*) FROM cli_login_codes WHERE expires_at<=now()),
		       (SELECT count(*) FROM cli_login_codes WHERE expires_at>now()),
		       (SELECT count(*) FROM oidc_transactions WHERE expires_at<=now()),
		       (SELECT count(*) FROM oidc_transactions WHERE expires_at>now())
	`).Scan(&policies, &sessions, &expiredCodes, &liveCodes, &expiredTransactions, &liveTransactions)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(policies, []string{"p-1", "p-1002"}) || !slices.Equal(sessions, []string{"active", "recent", "revoked"}) {
		t.Errorf("remaining policy tests=%v sessions=%v, want one expired policy test, the live policy test and three retained sessions", policies, sessions)
	}
	if expiredCodes != 0 || liveCodes != 1 || expiredTransactions != 0 || liveTransactions != 1 {
		t.Errorf("remaining login codes (expired=%d, live=%d), OIDC transactions (expired=%d, live=%d), want one live row each",
			expiredCodes, liveCodes, expiredTransactions, liveTransactions)
	}
	closed := make(chan struct{})
	go func() {
		f.service.Close()
		close(closed)
	}()
	select {
	case <-observer.canceled:
	case <-ctx.Done():
		t.Fatal("API Close did not cancel the in-flight sweep")
	}
	select {
	case <-closed:
		t.Error("API Close returned before the maintenance worker finished")
	case <-time.After(10 * time.Millisecond):
	}
	release()
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal("API Close did not join the maintenance worker")
	}
}

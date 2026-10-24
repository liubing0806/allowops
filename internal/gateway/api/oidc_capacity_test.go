package api

import (
	"context"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"golang.org/x/oauth2"
)

func oidcBeginRequest() *connect.Request[v1.BeginOidcLoginRequest] {
	return connect.NewRequest(&v1.BeginOidcLoginRequest{ProviderId: "test", Client: v1.LoginClient_LOGIN_CLIENT_CLI, CliLoopbackUri: "http://127.0.0.1:54321/callback", CliState: secret(""), CliCodeChallenge: oauth2.S256ChallengeFromVerifier(oauth2.GenerateVerifier())})
}

func seedOIDCCapacity(t *testing.T, f *fixture, n int) {
	t.Helper()
	// Seed a different provider: A47 caps the whole database, not each provider.
	_, err := f.db.Pool.Exec(context.Background(), `INSERT INTO oidc_transactions(state_hash,provider_id,client,nonce,provider_verifier,loopback_uri,cli_state,cli_challenge,expires_at) SELECT decode(lpad(to_hex(n),64,'0'),'hex'),'other-provider','cli','seed-nonce','seed-verifier','http://127.0.0.1:54321/callback','seed-state','seed-challenge',now()+interval '1 hour' FROM generate_series(1,$1::int) n`, n)
	if err != nil {
		t.Fatal(err)
	}
}

func TestOIDCBeginCleansExpiredAndPreservesLiveTransactions(t *testing.T) {
	f := newFixture(t)
	f.addOIDC(t, newOIDC(t))
	ctx := context.Background()
	f.service.Audit = NewAuditor(audit.New(f.db.Pool, audit.Config{}))
	states := []string{}
	for range 2 {
		begun, err := f.auth("").BeginOidcLogin(ctx, oidcBeginRequest())
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(begun.Msg.AuthorizationUrl)
		if err != nil {
			t.Fatal(err)
		}
		states = append(states, u.Query().Get("state"))
	}
	if _, err := f.db.Pool.Exec(ctx, `UPDATE oidc_transactions SET expires_at=now()-interval '1 second' WHERE state_hash=$1`, hash(states[0])); err != nil {
		t.Fatal(err)
	}
	if _, err := f.auth("").BeginOidcLogin(ctx, oidcBeginRequest()); err != nil {
		t.Fatal(err)
	}
	var expired, live, total int
	if err := f.db.Pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE expires_at<=now()),count(*) FILTER(WHERE state_hash=$1),count(*) FROM oidc_transactions`, hash(states[1])).Scan(&expired, &live, &total); err != nil {
		t.Fatal(err)
	}
	if expired != 0 || live != 1 || total != 2 {
		t.Fatalf("expired=%d preserved live=%d total=%d; want 0,1,2", expired, live, total)
	}
}

func TestOIDCGlobalCapacityRejectsAndCommitsExpiryCleanup(t *testing.T) {
	f := newFixture(t)
	f.addOIDC(t, newOIDC(t))
	ctx := context.Background()
	f.service.Audit = NewAuditor(audit.New(f.db.Pool, audit.Config{}))
	seedOIDCCapacity(t, f, 10002)
	if _, err := f.db.Pool.Exec(ctx, `UPDATE oidc_transactions SET expires_at=now()-interval '1 second' WHERE state_hash IN (decode(lpad(to_hex(10001),64,'0'),'hex'),decode(lpad(to_hex(10002),64,'0'),'hex'))`); err != nil {
		t.Fatal(err)
	}
	_, err := f.auth("").BeginOidcLogin(ctx, oidcBeginRequest())
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Errorf("full global capacity error=%v; want RESOURCE_EXHAUSTED", err)
	}
	var total, expired int
	if err := f.db.Pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE expires_at<=now()) FROM oidc_transactions`).Scan(&total, &expired); err != nil {
		t.Fatal(err)
	}
	if total != 10000 || expired != 0 {
		t.Errorf("rejected begin left total=%d expired=%d; want 10000,0", total, expired)
	}
}

func TestOIDCConsumptionReleasesGlobalCapacity(t *testing.T) {
	f := newFixture(t)
	provider := newOIDC(t)
	f.addOIDC(t, provider)
	ctx := context.Background()
	f.service.Audit = NewAuditor(audit.New(f.db.Pool, audit.Config{}))
	dest, cookie := f.begin(t, v1.LoginClient_LOGIN_CLIENT_CLI, oauth2.GenerateVerifier())
	seedOIDCCapacity(t, f, 9999)
	_, err := f.auth("").BeginOidcLogin(ctx, oidcBeginRequest())
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Errorf("full before consumption error=%v; want RESOURCE_EXHAUSTED", err)
	}
	if _, err = f.complete(t, provider, dest, cookie, dest.Query().Get("state")); err != nil {
		t.Fatal(err)
	}
	var consumed, total int
	if err = f.db.Pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE state_hash=$1),count(*) FROM oidc_transactions`, hash(dest.Query().Get("state"))).Scan(&consumed, &total); err != nil {
		t.Fatal(err)
	}
	if consumed != 0 || total != 9999 {
		t.Errorf("after consumption: consumed rows=%d total=%d; want 0,9999", consumed, total)
	}
	if _, err = f.auth("").BeginOidcLogin(ctx, oidcBeginRequest()); err != nil {
		t.Fatal(err)
	}
	if err = f.db.Pool.QueryRow(ctx, `SELECT count(*) FROM oidc_transactions`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 10000 {
		t.Errorf("replacement begin total=%d; want 10000", total)
	}
	_, err = f.complete(t, provider, dest, cookie, dest.Query().Get("state"))
	code(t, err, connect.CodeUnauthenticated)
}

func TestOIDCGlobalCapacityConcurrentInstances(t *testing.T) {
	f := newFixture(t)
	f.addOIDC(t, newOIDC(t))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	f.service.Audit = NewAuditor(audit.New(f.db.Pool, audit.Config{}))
	seedOIDCCapacity(t, f, 9999)
	peer, err := New(ctx, f.db, f.service.Config, NewAuditor(audit.New(f.db.Pool, audit.Config{})))
	if err != nil {
		t.Fatal(err)
	}
	peer.oidc["test"] = f.service.oidc["test"] // Same immutable provider, separate Service/HTTP handler.
	server := httptest.NewTLSServer(peer.Handler())
	defer server.Close()
	defer peer.Close()
	// Force both request transactions to be in-flight before any insertion can
	// finish. A count-then-unlocked-insert implementation admits both at cap-1.
	_, err = f.db.Pool.Exec(ctx, `CREATE FUNCTION gate_oidc_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(64182002); RETURN NEW; END $$; CREATE TRIGGER gate_oidc_insert BEFORE INSERT ON oidc_transactions FOR EACH ROW EXECUTE FUNCTION gate_oidc_insert()`)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := f.db.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Release()
	if _, err = gate.Exec(ctx, `SELECT pg_advisory_lock(64182002)`); err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			if _, err := gate.Exec(context.Background(), `SELECT pg_advisory_unlock(64182002)`); err != nil {
				t.Error(err)
			}
			released = true
		}
	}
	defer release()
	results := make(chan error, 2)
	clients := []rpc.AuthServiceClient{f.auth(""), rpc.NewAuthServiceClient(server.Client(), server.URL)}
	for _, client := range clients {
		go func() { _, err := client.BeginOidcLogin(ctx, oidcBeginRequest()); results <- err }()
	}
	deadline := time.Now().Add(10 * time.Second)
	blocked := 0
	for time.Now().Before(deadline) {
		if err := f.db.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())`).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if blocked != 2 {
		t.Fatalf("test gate: blocked request transactions=%d; want 2", blocked)
	}
	release()
	admitted, rejected := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			admitted++
		} else if connect.CodeOf(err) == connect.CodeResourceExhausted {
			rejected++
		} else {
			t.Errorf("concurrent begin error=%v", err)
		}
	}
	var total int
	if err = f.db.Pool.QueryRow(ctx, `SELECT count(*) FROM oidc_transactions`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if admitted != 1 || rejected != 1 || total != 10000 {
		t.Fatalf("concurrent admitted=%d rejected=%d total=%d; want 1,1,10000", admitted, rejected, total)
	}
}

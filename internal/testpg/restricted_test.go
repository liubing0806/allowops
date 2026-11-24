package testpg_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/catalogsvc"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/liubing0806/allowops/internal/testpg"
)

func requireOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func openStore(t *testing.T, dsn string) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), dsn)
	requireOK(t, err)
	t.Cleanup(st.Close)
	return st
}

func registerHost(t *testing.T, st *store.Store) string {
	t.Helper()
	ctx := t.Context()
	token, err := st.CreateJoinToken(ctx, 1, time.Hour)
	requireOK(t, err)
	id, err := st.Register(ctx, token, "runtime-host", func(string) (string, time.Time, error) {
		return "initial", time.Now().Add(time.Hour), nil
	})
	requireOK(t, err)
	requireOK(t, st.CheckIdentity(ctx, id, "initial"))
	return id
}

func publishCatalog(t *testing.T, st *store.Store) map[string]ed25519.PublicKey {
	t.Helper()
	publicKey, key, err := ed25519.GenerateKey(rand.Reader)
	requireOK(t, err)
	pkg, err := catalog.Build(&catalog.Catalog{
		Config: catalog.Config{SchemaVersion: 1, CatalogID: "runtime"},
		Actions: map[string]catalog.Action{
			"probe": {Name: "probe", Description: "Host probe", Risk: "read", Exec: []any{"/usr/bin/true"}, Timeout: "1s", MaxOutput: 1024},
		},
	}, catalog.BuildOptions{})
	requireOK(t, err)
	payload, err := catalog.CanonicalJSON(pkg)
	requireOK(t, err)
	envelope, err := catalog.Sign(payload, catalog.SigningKey{PrivateKey: key})
	requireOK(t, err)
	raw, err := json.Marshal(envelope)
	requireOK(t, err)
	trusted := map[string]ed25519.PublicKey{catalog.KeyID(publicKey): publicKey}
	publication := catalogsvc.Service{Store: st, Trusted: trusted, MaxEnvelopeBytes: 1 << 20, MaxActionBytes: 256 << 10}
	_, err = publication.Publish(t.Context(), raw)
	requireOK(t, err)
	return trusted
}

func TestRuntimeRole(t *testing.T) {
	pair := testpg.StartPair(t)
	st := openStore(t, pair.RuntimeDSN)

	t.Run("identity_and_schema", func(t *testing.T) {
		ctx := t.Context()
		requireOK(t, st.CheckSchema(ctx))
		var name string
		var superuser, createDB, createRole, maintenance, writer, createSchemaObjects bool
		err := st.Pool.QueryRow(ctx, `SELECT rolname, rolsuper, rolcreatedb, rolcreaterole,
			pg_has_role(current_user, 'fixture', 'MEMBER'),
			pg_has_role(current_user, 'allowops_audit_writer', 'USAGE'),
			has_schema_privilege(current_user, 'public', 'CREATE')
			FROM pg_roles WHERE rolname = current_user`).
			Scan(&name, &superuser, &createDB, &createRole, &maintenance, &writer, &createSchemaObjects)
		requireOK(t, err)
		if name != pair.RuntimeRole || superuser || createDB || createRole || maintenance || !writer || createSchemaObjects {
			t.Fatalf("login=%q superuser=%t createdb=%t createrole=%t maintenance_member=%t audit_writer=%t public_create=%t",
				name, superuser, createDB, createRole, maintenance, writer, createSchemaObjects)
		}
	})

	t.Run("host_lifecycle", func(t *testing.T) {
		ctx := t.Context()
		id := registerHost(t, st)
		requireOK(t, st.Renew(ctx, id, "initial", func() (string, time.Time, error) {
			return "renewed", time.Now().Add(time.Hour), nil
		}))
		requireOK(t, st.CheckIdentity(ctx, id, "renewed"))
		requireOK(t, st.DeleteHost(ctx, id))
		if err := st.CheckIdentity(ctx, id, "renewed"); !errors.Is(err, store.ErrCredential) {
			t.Fatalf("deleted host identity: got %v, want ErrCredential", err)
		}
	})

	t.Run("catalog_publish", func(t *testing.T) {
		publishCatalog(t, st)
		current, err := st.Queries.CurrentCatalogs(t.Context())
		requireOK(t, err)
		if len(current) != 1 || current[0].CatalogID != "runtime" || !slices.Equal(current[0].ActionNames, []string{"probe"}) {
			t.Fatalf("unexpected published catalogs: %+v", current)
		}
	})

	t.Run("audit_append_and_export", func(t *testing.T) {
		ctx := t.Context()
		log := audit.New(st.Pool, audit.Config{})
		event, err := log.Append(ctx, audit.Payload{Operation: "host_probe"})
		requireOK(t, err)
		exporter := audit.Exporter{Store: log, Cursor: "runtime", Storage: audit.FileStorage{Directory: t.TempDir(), MaxBytes: 1 << 20}}
		count, err := exporter.Once(ctx)
		requireOK(t, err)
		var next int64
		requireOK(t, st.Pool.QueryRow(ctx, "SELECT next_seq FROM audit_export_cursors WHERE name=$1", exporter.Cursor).Scan(&next))
		if count != 1 || next != int64(event.Seq)+1 {
			t.Fatalf("exported=%d next_seq=%d, want 1 and %d", count, next, event.Seq+1)
		}
	})

	t.Run("business_table_crud", func(t *testing.T) {
		ctx := t.Context()
		_, err := st.Pool.Exec(ctx, "INSERT INTO roles(name) VALUES ('dispatcher')")
		requireOK(t, err)
		_, err = st.Pool.Exec(ctx, "UPDATE roles SET description='dispatch jobs' WHERE name='dispatcher'")
		requireOK(t, err)
		var description string
		requireOK(t, st.Pool.QueryRow(ctx, "SELECT description FROM roles WHERE name='dispatcher'").Scan(&description))
		deleted, err := st.Pool.Exec(ctx, "DELETE FROM roles WHERE name='dispatcher'")
		requireOK(t, err)
		if description != "dispatch jobs" || deleted.RowsAffected() != 1 {
			t.Fatalf("description=%q deleted=%d", description, deleted.RowsAffected())
		}
	})

	for _, tc := range []struct{ name, sql string }{
		{"set_audit_writer", "SET ROLE allowops_audit_writer"},
		{"audit_update", "UPDATE audit_events SET reason='changed'"},
		{"audit_delete", "DELETE FROM audit_events"},
		{"audit_truncate", "TRUNCATE audit_events"},
		{"audit_create_partitions", "SELECT audit_create_partitions(now(), 1)"},
		{"audit_boundary_update", "UPDATE audit_boundary SET seq=0"},
		{"audit_cursor_delete", "DELETE FROM audit_export_cursors"},
		{"audit_partition_registry", "SELECT * FROM audit_partitions"},
		{"migration_insert", "INSERT INTO goose_db_version(version_id,is_applied) VALUES (999,true)"},
		{"migration_sequence", "SELECT nextval(pg_get_serial_sequence('public.goose_db_version','id'))"},
		{"create_table", "CREATE TABLE rogue_table (id int)"},
		{"create_task_partition", "CREATE TABLE tasks_209901 PARTITION OF tasks FOR VALUES FROM ('2099-01-01T00:00:00Z') TO ('2099-02-01T00:00:00Z')"},
		{"drop_hosts", "DROP TABLE hosts"},
	} {
		t.Run("denied/"+tc.name, func(t *testing.T) {
			_, err := st.Pool.Exec(t.Context(), tc.sql)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Fatalf("%s: got %v, want SQLSTATE 42501", tc.sql, err)
			}
		})
	}

	t.Run("table_and_partition_privileges", func(t *testing.T) {
		ctx := t.Context()
		admin := openStore(t, pair.AdminDSN)
		// Maintenance may attach a child with any name. Reapplying the deployment
		// manifest must cover it without relying on a partition-name prefix.
		_, err := admin.Pool.Exec(ctx, `CREATE TABLE maintenance_batch PARTITION OF public.tasks
			FOR VALUES FROM ('2098-01-01T00:00:00Z') TO ('2098-02-01T00:00:00Z')`)
		requireOK(t, err)
		requireOK(t, testpg.ApplyRuntimeGrants(ctx, admin.Pool, pair.RuntimeRole))

		// Discover the migrated relations independently of the manifest. A new
		// business table omitted from the grant list must fail this assertion.
		rows, err := st.Pool.Query(ctx, `SELECT relname,
			oid IN (SELECT relid FROM pg_partition_tree('public.audit_events')),
			pg_has_role(current_user, relowner, 'MEMBER'),
			ARRAY(SELECT p FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']) p
			      WHERE has_table_privilege(current_user, oid, p))
			FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind IN ('r','p')
			ORDER BY relname`)
		requireOK(t, err)
		defer rows.Close()
		for rows.Next() {
			var table string
			var eventTable, owner bool
			var privileges []string
			requireOK(t, rows.Scan(&table, &eventTable, &owner, &privileges))
			want := []string{"SELECT", "INSERT", "UPDATE", "DELETE"}
			switch {
			case eventTable:
				want = []string{"SELECT", "INSERT"}
			case table == "audit_export_cursors":
				want = []string{"SELECT", "INSERT", "UPDATE"}
			case table == "audit_boundary", table == "goose_db_version":
				want = []string{"SELECT"}
			case table == "audit_partitions":
				want = nil
			}
			if owner || !slices.Equal(privileges, want) {
				t.Errorf("%s: owner=%t privileges=%v, want non-owner with %v", table, owner, privileges, want)
			}
		}
		requireOK(t, rows.Err())
	})

	t.Run("reject_maintenance_member", func(t *testing.T) {
		ctx := t.Context()
		admin := openStore(t, pair.AdminDSN)
		_, err := admin.Pool.Exec(ctx, "CREATE ROLE maintenance_member LOGIN; GRANT fixture TO maintenance_member")
		requireOK(t, err)
		if err := testpg.ApplyRuntimeGrants(ctx, admin.Pool, "maintenance_member"); err == nil {
			t.Fatal("grants accepted a member of the maintenance role")
		}
		var directGrant bool
		requireOK(t, admin.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_auth_members
			WHERE roleid='allowops_audit_writer'::regrole AND member='maintenance_member'::regrole)`).Scan(&directGrant))
		if directGrant {
			t.Fatal("rejected manifest committed audit writer membership")
		}
	})

	t.Run("reject_other_grantor_options", func(t *testing.T) {
		admin := openStore(t, pair.AdminDSN)
		_, err := admin.Pool.Exec(t.Context(), `
			CREATE ROLE previous_grantor;
			GRANT allowops_audit_writer TO previous_grantor WITH ADMIN TRUE;
			CREATE ROLE "LegacySet" LOGIN;
			CREATE ROLE "LegacyAdmin" LOGIN;
			SET LOCAL ROLE previous_grantor;
			GRANT allowops_audit_writer TO "LegacySet" WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;
			GRANT allowops_audit_writer TO "LegacyAdmin" WITH INHERIT FALSE, SET FALSE, ADMIN TRUE;`)
		requireOK(t, err)
		for _, tc := range []struct {
			role             string
			canSet, canAdmin bool
		}{{"LegacySet", true, false}, {"LegacyAdmin", false, true}} {
			t.Run(tc.role, func(t *testing.T) {
				ctx := t.Context()
				err := testpg.ApplyRuntimeGrants(ctx, admin.Pool, tc.role)
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) || pgErr.Code != "P0001" || !strings.Contains(pgErr.Message, "without SET or ADMIN options") {
					t.Errorf("apply grants to %s: got %v, want rejection of existing membership options", tc.role, err)
				}
				var total, original int
				requireOK(t, admin.Pool.QueryRow(ctx, `SELECT count(*),
					count(*) FILTER (WHERE grantor='previous_grantor'::regrole AND set_option=$2 AND admin_option=$3)
					FROM pg_auth_members WHERE roleid='allowops_audit_writer'::regrole
					AND member=(SELECT oid FROM pg_roles WHERE rolname=$1)`, tc.role, tc.canSet, tc.canAdmin).Scan(&total, &original))
				if total != 1 || original != 1 {
					t.Errorf("%s writer grants after rejection: total=%d original=%d, want only the original grant", tc.role, total, original)
				}
			})
		}
	})

	t.Run("psql_without_single_transaction", func(t *testing.T) {
		ctx := t.Context()
		admin := openStore(t, pair.AdminDSN)
		_, err := admin.Pool.Exec(ctx, `CREATE ROLE rejected_login LOGIN CREATEDB;
			CREATE ROLE untargeted_login LOGIN;
			GRANT CREATE ON SCHEMA public TO rejected_login`)
		requireOK(t, err)

		// Use the fixture's own psql so it parses the deployment file and commits
		// each statement, just as it does when an operator omits -1.
		const dockerHost = "--host=unix:///var/run/docker.sock"
		port := admin.Pool.Config().ConnConfig.Port
		ids, err := exec.CommandContext(ctx, "docker", dockerHost, "ps", "-q",
			"--filter", "ancestor="+testpg.Image, "--filter", fmt.Sprintf("publish=%d/tcp", port)).Output()
		requireOK(t, err)
		containers := strings.Fields(string(ids))
		if len(containers) != 1 {
			t.Fatalf("expected one fixture publishing port %d, found %v", port, containers)
		}
		manifest, err := os.ReadFile("../../deploy/sql/runtime-grants.sql")
		requireOK(t, err)
		for _, options := range []string{"", "-c allowops.runtime_role=untargeted_login"} {
			psql := exec.CommandContext(ctx, "docker", dockerHost, "exec", "-i", "-e", "PGOPTIONS="+options, containers[0],
				"psql", "-X", "-U", "fixture", "-d", "fixture", "-v", "ON_ERROR_STOP=1", "-v", "runtime_role=rejected_login", "-f", "-")
			psql.Stdin = bytes.NewReader(manifest)
			out, err := psql.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 || !strings.Contains(string(out), "Missing transaction-local runtime role") {
				t.Errorf("psql without -1, PGOPTIONS=%q: got %v, want missing transaction-local role (exit 3)\n%s", options, err, out)
			}
			var memberships int
			var schemaCreate bool
			requireOK(t, admin.Pool.QueryRow(ctx, `SELECT count(*), has_schema_privilege('rejected_login','public','CREATE')
				FROM pg_auth_members WHERE member IN ('rejected_login'::regrole, 'untargeted_login'::regrole)`).Scan(&memberships, &schemaCreate))
			if memberships != 0 || !schemaCreate {
				t.Errorf("PGOPTIONS=%q: memberships=%d public.CREATE=%t, want 0 and original CREATE privilege", options, memberships, schemaCreate)
			}
		}
	})
}

func TestApplyRuntimeGrantsRejectsInvalidIdentifier(t *testing.T) {
	for _, name := range []string{"", "a;b", "gateway\x00role", strings.Repeat("a", 64)} {
		if err := testpg.ApplyRuntimeGrants(t.Context(), nil, name); err == nil {
			t.Errorf("accepted invalid role %q", name)
		}
	}
}

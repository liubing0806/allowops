package testpg

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DSNSet identifies the migration owner and the gateway login on one disposable database.
type DSNSet struct {
	AdminDSN    string
	RuntimeDSN  string
	RuntimeRole string
}

func repositoryRoot() (string, error) {
	if _, source, _, ok := runtime.Caller(0); ok && filepath.IsAbs(source) {
		return filepath.Join(filepath.Dir(source), "..", ".."), nil
	}
	// With -trimpath the source filename is relative. Go runs package tests
	// in their package directory, even when testpg is used by another package.
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		} else if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not locate AllowOps go.mod from the test working directory")
		}
		dir = parent
	}
}

var roleIdentifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z_0-9$]{0,62}$`)

// ApplyRuntimeGrants applies the deployment manifest to an existing login.
// Supply a simple ASCII PostgreSQL identifier of at most 63 bytes, with its exact case.
func ApplyRuntimeGrants(ctx context.Context, adminPool *pgxpool.Pool, runtimeRole string) error {
	if !roleIdentifier.MatchString(runtimeRole) {
		return fmt.Errorf("invalid PostgreSQL role identifier %q", runtimeRole)
	}
	root, err := repositoryRoot()
	if err != nil {
		return err
	}
	manifest, err := os.ReadFile(filepath.Join(root, "deploy", "sql", "runtime-grants.sql"))
	if err != nil {
		return err
	}
	sql := strings.ReplaceAll(string(manifest), `:"runtime_role"`, pgx.Identifier{runtimeRole}.Sanitize())
	return pgx.BeginFunc(ctx, adminPool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, sql)
		return err
	})
}

// StartPair migrates a fresh local database and provisions its restricted gateway login.
func StartPair(t *testing.T) DSNSet {
	t.Helper()
	adminDSN := Start(t)
	ctx := t.Context()
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	// The store package's own tests import testpg. Its migration command calls
	// store.Migrate without introducing an import cycle into those tests.
	migrate := exec.CommandContext(ctx, "go", "run", "./cmd/allowops-gateway", "migrate")
	migrate.Dir = root
	migrate.Env = append(os.Environ(), "ALLOWOPS_DATABASE_URL="+adminDSN)
	if output, err := migrate.CombinedOutput(); err != nil {
		t.Fatalf("allowops-gateway migrate: %v\n%s", err, output)
	}
	admin, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Fatal("configure fixture maintenance pool")
	}
	defer admin.Close()
	const role = "allowops_runtime"
	password := rand.Text()
	_, err = admin.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+
		" NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT LOGIN PASSWORD $1", pgx.QueryExecModeSimpleProtocol, password)
	if err != nil {
		t.Fatalf("create fixture runtime login: %v", err)
	}
	if err := ApplyRuntimeGrants(ctx, admin, role); err != nil {
		t.Fatalf("apply runtime grants: %v", err)
	}
	runtimeURL, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatal("parse fixture maintenance URL")
	}
	runtimeURL.User = url.UserPassword(role, password)
	return DSNSet{AdminDSN: adminDSN, RuntimeDSN: runtimeURL.String(), RuntimeRole: role}
}

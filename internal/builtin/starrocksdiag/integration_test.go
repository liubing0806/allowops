package starrocksdiag

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"

	"github.com/liubing0806/allowops/internal/builtin/credfile"
)

// The integration tests need the local environment of test/starrocks-dremio
// (./test/starrocks-dremio/up.sh). They run only when ALLOWOPS_STARROCKS_ADDR
// is set, for example to 127.0.0.1:29030. Account passwords are read from
// ALLOWOPS_STARROCKS_STATE (default: test/starrocks-dremio/.state) inside the
// test process; they are never logged or passed in arguments.
//
// The accounts: sr_diag (SELECT on the demo and audit databases plus SYSTEM
// OPERATE, the account of section 4.9 of the plan) and sr_query (SELECT on
// the demo database only).
const (
	envAddr   = "ALLOWOPS_STARROCKS_ADDR"
	envState  = "ALLOWOPS_STARROCKS_STATE"
	envHelper = "ALLOWOPS_STARROCKS_ROOT_HELPER"
)

func integrationAddress(t *testing.T) string {
	t.Helper()
	addr := os.Getenv(envAddr)
	if addr == "" {
		t.Skipf("%s is not set; start the local environment (test/starrocks-dremio/up.sh) and set it to the FE MySQL address, for example 127.0.0.1:29030", envAddr)
	}
	if !strings.HasPrefix(addr, "tcp://") {
		addr = "tcp://" + addr
	}
	return addr
}

func stateCredential(t *testing.T, key string) credfile.Credential {
	t.Helper()
	dir := os.Getenv(envState)
	if dir == "" {
		dir = filepath.Join("..", "..", "..", "test", "starrocks-dremio", ".state")
	}
	data, err := os.ReadFile(filepath.Join(dir, "credentials.json"))
	if err != nil {
		t.Fatalf("read credentials of the local environment: %v", err)
	}
	var accounts map[string]struct{ UserName, Password string }
	if err := json.Unmarshal(data, &accounts); err != nil {
		t.Fatal("parse credentials of the local environment")
	}
	account, ok := accounts[key]
	if !ok || account.UserName == "" {
		t.Fatalf("no account %q in the local environment", key)
	}
	return credfile.Credential{Username: account.UserName, Password: account.Password}
}

func integrationConfig(address string) Config {
	return Config{Address: address, Timeout: 10 * time.Second}
}

// profileOf runs sqlText on a connection of the query account with
// enable_profile and returns its query ID, the way a user's session would.
func profileOf(t *testing.T, address string, sqlText string, presets ...string) string {
	t.Helper()
	cred := stateCredential(t, "sr_query")
	dc := mysqldriver.NewConfig()
	dc.User, dc.Passwd, dc.Net, dc.Addr = cred.Username, cred.Password, "tcp", strings.TrimPrefix(address, "tcp://")
	connector, err := mysqldriver.NewConnector(dc)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, stmt := range append([]string{"SET enable_profile = true"}, presets...) {
		if _, err := conn.ExecContext(context.Background(), stmt); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := conn.QueryContext(context.Background(), sqlText)
	if err == nil {
		for rows.Next() {
		}
		err = rows.Err()
		rows.Close()
	}
	if err != nil && !strings.Contains(sqlText, "query_mem_limit") {
		t.Logf("the query failed (expected only for memory limit tests): %v", err)
	}
	var id string
	if err := conn.QueryRowContext(context.Background(), "SELECT last_query_id()").Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func diagRun(t *testing.T, cfg Config, p Params) Result {
	t.Helper()
	got, err := runWithCredential(context.Background(), cfg.normalized(), p, stateCredential(t, "sr_diag"), nil)
	if err != nil {
		t.Fatalf("%+v: %v", p, err)
	}
	return got
}

func waitForProfile(t *testing.T, address, id string) Result {
	t.Helper()
	cfg := integrationConfig(address)
	deadline := time.Now().Add(40 * time.Second)
	for {
		got, err := runWithCredential(context.Background(), cfg.normalized(), Params{Op: "profile_summary", QueryID: id}, stateCredential(t, "sr_diag"), nil)
		if err == nil {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("no profile for %s: %v", id, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

type summaryJSON struct {
	Query struct {
		QueryID string `json:"query_id"`
		State   string `json:"state"`
	} `json:"query"`
	TopOperators []struct {
		Operator   string  `json:"operator"`
		PlanNodeID int     `json:"plan_node_id"`
		TimePct    float64 `json:"time_percent"`
	} `json:"top_operators"`
	Findings []struct {
		Rule string `json:"rule"`
	} `json:"findings"`
	ResultRows *int `json:"result_rows"`
}

func decodeSummary(t *testing.T, output string) summaryJSON {
	t.Helper()
	var s summaryJSON
	if err := json.Unmarshal([]byte(output), &s); err != nil {
		t.Fatalf("not JSON: %v\n%.500s", err, output)
	}
	return s
}

func (s summaryJSON) rules() []string {
	var ids []string
	for _, f := range s.Findings {
		ids = append(ids, f.Rule)
	}
	return ids
}

func TestIntegrationCluster(t *testing.T) {
	address := integrationAddress(t)
	cfg := integrationConfig(address)
	got := diagRun(t, cfg, Params{Op: "cluster"})
	for _, want := range []string{"# frontends\n", "# backends\n", "# compute_nodes\n", "LEADER", "Alive"} {
		if !strings.Contains(got.Output, want) {
			t.Errorf("cluster output lacks %q:\n%s", want, got.Output)
		}
	}
	if got.Truncated {
		t.Errorf("truncated: %+v", got)
	}
	got = diagRun(t, cfg, Params{Op: "cluster", Component: "backends"})
	if strings.Contains(got.Output, "# frontends") || !strings.Contains(got.Output, "# backends\n") || got.Rows < 1 {
		t.Errorf("backends only:\n%s", got.Output)
	}
}

func TestIntegrationRunning(t *testing.T) {
	address := integrationAddress(t)
	cfg := integrationConfig(address)
	// A slow query from another account: bypass the guards on purpose.
	cred := stateCredential(t, "sr_query")
	dc := mysqldriver.NewConfig()
	dc.User, dc.Passwd, dc.Net, dc.Addr = cred.Username, cred.Password, "tcp", strings.TrimPrefix(address, "tcp://")
	connector, _ := mysqldriver.NewConnector(dc)
	db := sql.OpenDB(connector)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		rows, err := db.QueryContext(ctx, "SELECT sleep(6)")
		if err == nil {
			rows.Close()
		}
	}()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		got := diagRun(t, cfg, Params{Op: "running"})
		if strings.Contains(got.Output, "QueryId") && strings.Contains(got.Output, "allowops_query") {
			if !strings.Contains(got.Output, "ExecTime") || strings.Contains(got.Output, "sleep") {
				t.Errorf("columns: %s", got.Output)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the running query is not listed:\n%s", got.Output)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func TestIntegrationSlowQueriesUseTheAuditTable(t *testing.T) {
	address := integrationAddress(t)
	cfg := integrationConfig(address)
	// The synthetic audit table has 200 rows spread over 7 minutes * 200 = 23 hours, 20 of them slow (12 s and more).
	got := diagRun(t, cfg, Params{Op: "slow_queries", SinceMinutes: 10080, MinDurationMs: 10000, State: "any", Limit: 50})
	lines := strings.Split(strings.TrimSpace(got.Output), "\n")
	if lines[0] != "query_id\ttimestamp\tuser\tdb\tstate\tquery_time\tscan_bytes\tscan_rows\treturn_rows\tcpu_cost_ns\tmem_cost_bytes\tstmt" {
		t.Fatalf("header: %q", lines[0])
	}
	if len(lines) < 10 || len(lines) > 21 || got.Truncated {
		t.Errorf("%d slow rows: %+v", len(lines)-1, got)
	}
	last := int64(1 << 62)
	for _, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		var ms int64
		if err := json.Unmarshal([]byte(fields[5]), &ms); err != nil || ms < 10000 || ms > last {
			t.Errorf("rows must be ordered by query time, all at least 10 s: %q", line)
		}
		last = ms
	}
	got = diagRun(t, cfg, Params{Op: "slow_queries", SinceMinutes: 10080, MinDurationMs: 0, State: "ERR", Limit: 500})
	if got.Rows < 5 || strings.Contains(got.Output, "\tEOF\t") || !strings.Contains(got.Output, "\tERR\t") {
		t.Errorf("state ERR: %d rows\n%.600s", got.Rows, got.Output)
	}
	got = diagRun(t, cfg, Params{Op: "slow_queries", SinceMinutes: 60, MinDurationMs: 0, State: "any", Limit: 500})
	if got.Rows > 10 {
		t.Errorf("one hour window returned %d rows", got.Rows)
	}
	got = diagRun(t, cfg, Params{Op: "slow_queries", SinceMinutes: 10080, MinDurationMs: 0, State: "any", Limit: 2})
	if got.Rows != 2 {
		t.Errorf("limit 2 returned %d rows", got.Rows)
	}
	// A renamed table is read as configured.
	renamed := cfg
	renamed.AuditTable = "starrocks_audit_db__.no_such_audit_table"
	if _, err := runWithCredential(context.Background(), renamed.normalized(), Params{Op: "slow_queries", SinceMinutes: 60, State: "any", Limit: 1}, stateCredential(t, "sr_diag"), nil); err == nil || err.Error() != "starrocks query failed (code 5502)" {
		t.Errorf("renamed table: %v", err)
	}
}

func TestIntegrationProfileListAnalyzeSummary(t *testing.T) {
	address := integrationAddress(t)
	cfg := integrationConfig(address)
	id := profileOf(t, address, "SELECT store_id, sum(amount) FROM demo_dw.fact_orders GROUP BY store_id")
	summary := waitForProfile(t, address, id)
	s := decodeSummary(t, summary.Output)
	if s.Query.QueryID != id || s.Query.State != "Finished" || len(s.TopOperators) == 0 || s.TopOperators[0].Operator != "OLAP_SCAN" {
		t.Errorf("summary of %s: %.600s", id, summary.Output)
	}
	if strings.Contains(summary.Output, "fact_orders") || strings.Contains(summary.Output, "SELECT") {
		t.Errorf("the summary contains SQL text: %.600s", summary.Output)
	}
	list := diagRun(t, cfg, Params{Op: "profile_list", Limit: 50})
	if !strings.Contains(list.Output, id) {
		t.Errorf("profile list lacks %s:\n%.800s", id, list.Output)
	}
	if got := diagRun(t, cfg, Params{Op: "profile_list", Limit: 1}); got.Rows != 1 {
		t.Errorf("limit 1 returned %d rows", got.Rows)
	}
	analyze := diagRun(t, cfg, Params{Op: "profile_analyze", QueryID: id})
	if !strings.Contains(analyze.Output, "Summary") || !strings.Contains(analyze.Output, "OLAP_SCAN") || strings.Contains(analyze.Output, "\x1b") || strings.Contains(analyze.Output, "[0m") {
		t.Errorf("analyze output:\n%.800s", analyze.Output)
	}
	// An unknown query ID has no profile.
	_, err := runWithCredential(context.Background(), cfg.normalized(), Params{Op: "profile_summary", QueryID: "00000000-0000-4000-8000-000000000000"}, stateCredential(t, "sr_diag"), nil)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("unknown query id: %v", err)
	}
}

// Real profiles produced by the local server give the documented findings
// through the whole path: server, get_query_profile, parser, rules.
func TestIntegrationRulesOnLiveProfiles(t *testing.T) {
	address := integrationAddress(t)
	for _, tc := range []struct {
		name, sql string
		presets   []string
		rule      string
	}{
		{"nested loop join", "SELECT count(*) FROM demo_dw.fact_orders f JOIN demo_dw.dim_product p ON f.amount > p.price * 20 AND f.product_id < p.product_id WHERE f.order_id <= 20000", nil, "SR-JOIN-1"},
		{"join expansion", "SELECT count(*) FROM demo_dw.fact_orders a JOIN demo_dw.fact_orders b ON a.store_id = b.store_id WHERE a.order_id < 2000", nil, "SR-JOIN-2"},
		{"projection", "SELECT count(*) FROM (SELECT regexp_replace(origin_data, '[a-z]+', 'yy') AS x FROM demo_dw.fact_orders ORDER BY order_id LIMIT 400000) t WHERE length(x) > 0", nil, "SR-PROJ-1"},
		{"memory limit", "SELECT k, count(*) FROM (SELECT order_id AS k, origin_data FROM demo_dw.fact_orders) t GROUP BY k, origin_data ORDER BY 2 DESC LIMIT 5", []string{"SET query_mem_limit = 50000000"}, "SR-MEM-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := profileOf(t, address, tc.sql, tc.presets...)
			s := decodeSummary(t, waitForProfile(t, address, id).Output)
			found := false
			for _, r := range s.rules() {
				found = found || r == tc.rule
			}
			if !found {
				t.Errorf("%s: rules %v", tc.rule, s.rules())
			}
		})
	}
}

func TestIntegrationProfileRun(t *testing.T) {
	address := integrationAddress(t)
	cfg := integrationConfig(address)
	cfg.AllowProfileRun = true
	got := diagRun(t, cfg, Params{Op: "profile_run", SQL: "SELECT count(*) FROM demo_dw.fact_orders a JOIN demo_dw.fact_orders b ON a.store_id = b.store_id WHERE a.order_id < 2000"})
	s := decodeSummary(t, got.Output)
	if s.ResultRows == nil || *s.ResultRows != 1 || s.Query.State != "Finished" || len(s.TopOperators) == 0 {
		t.Fatalf("summary: %.600s", got.Output)
	}
	hit := false
	for _, r := range s.rules() {
		hit = hit || r == "SR-JOIN-2"
	}
	if !hit {
		t.Errorf("rules %v", s.rules())
	}
	// Result rows are never returned.
	got = diagRun(t, cfg, Params{Op: "profile_run", Database: "demo_dw", SQL: "SELECT city, count(*) FROM dim_user GROUP BY city"})
	if s := decodeSummary(t, got.Output); s.ResultRows == nil || *s.ResultRows < 2 {
		t.Errorf("result rows: %.300s", got.Output)
	}
	for _, city := range []string{"Beijing", "Shanghai", "city"} {
		if strings.Contains(got.Output, city) {
			t.Errorf("result data in the output: %.600s", got.Output)
		}
	}
	// Disabled by default.
	if _, err := runWithCredential(context.Background(), integrationConfig(address).normalized(), Params{Op: "profile_run", SQL: "SELECT 1"}, stateCredential(t, "sr_diag"), nil); err == nil {
		t.Error("profile_run ran while disabled")
	}
	// A server error shows its code only.
	_, err := runWithCredential(context.Background(), cfg.normalized(), Params{Op: "profile_run", SQL: "SELECT * FROM demo_dw.no_such_secret_table"}, stateCredential(t, "sr_diag"), nil)
	if err == nil || err.Error() != "starrocks query failed (code 5502)" {
		t.Errorf("error: %v", err)
	}
	// The query timeout applies to the caller's SQL.
	short := cfg
	short.Timeout = time.Second
	start := time.Now()
	_, err = runWithCredential(context.Background(), short.normalized(), Params{Op: "profile_run", SQL: "SELECT count(*) FROM demo_dw.fact_orders a JOIN demo_dw.fact_orders b ON a.store_id <= b.store_id JOIN demo_dw.fact_orders c ON b.store_id <= c.store_id"}, stateCredential(t, "sr_diag"), nil)
	if err == nil || time.Since(start) > 6*time.Second {
		t.Errorf("slow run: %v after %v", err, time.Since(start))
	}
}

// The query account has no SYSTEM OPERATE and no right to the audit table:
// the diag ops need the diag account (section 4.9).
func TestIntegrationQueryAccountCannotDiagnose(t *testing.T) {
	address := integrationAddress(t)
	cfg := integrationConfig(address).normalized()
	cred := stateCredential(t, "sr_query")
	for _, p := range []Params{{Op: "cluster"}, {Op: "running"}, {Op: "slow_queries", SinceMinutes: 60, State: "any", Limit: 1}} {
		_, err := runWithCredential(context.Background(), cfg, p, cred, nil)
		if err == nil || err.Error() != "starrocks query failed (code 5203)" {
			t.Errorf("%s: %v", p.Op, err)
		}
	}
}

// The public Run applies the credential file rules, so it needs a root-owned
// file. The helper below runs as root in a user namespace (unshare -Ur maps
// the current user to uid 0); the credential check stays as strict as in production.
func TestIntegrationPublicRunAsRoot(t *testing.T) {
	address := integrationAddress(t)
	if os.Getenv(envHelper) == "1" {
		t.Skip("the helper runs in TestIntegrationRootHelper")
	}
	if os.Geteuid() == 0 {
		t.Skip("already root; run TestIntegrationRootHelper directly with " + envHelper + "=1")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("unshare", "-Ur", "true").CombinedOutput(); err != nil {
		t.Skipf("cannot create a user namespace (unshare -Ur): %v %s", err, out)
	}
	cmd := exec.Command("unshare", "-Ur", exe, "-test.run=^TestIntegrationRootHelper$", "-test.v", "-test.timeout=5m")
	cmd.Env = append(os.Environ(), envHelper+"=1", envAddr+"="+strings.TrimPrefix(address, "tcp://"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("root helper failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "--- PASS: TestIntegrationRootHelper") {
		t.Fatalf("root helper did not run:\n%s", out)
	}
}

func writeCredentialFile(t *testing.T, dir, name string, cred credfile.Credential, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestIntegrationRootHelper(t *testing.T) {
	if os.Getenv(envHelper) != "1" {
		t.Skip("runs only as a child of TestIntegrationPublicRunAsRoot")
	}
	if os.Geteuid() != 0 {
		t.Fatal("helper must run as root")
	}
	address := integrationAddress(t)
	dir := t.TempDir()
	diagFile := writeCredentialFile(t, dir, "diag.json", stateCredential(t, "sr_diag"), 0600)
	looseFile := writeCredentialFile(t, dir, "loose.json", stateCredential(t, "sr_diag"), 0644)
	cfg := Config{Credential: diagFile, Address: address}
	ctx := context.Background()

	got, err := Run(ctx, cfg, Params{Op: "cluster"})
	if err != nil || !strings.Contains(got.Output, "# frontends") {
		t.Errorf("cluster: %+v, %v", got, err)
	}
	if got, err = Run(ctx, cfg, Params{Op: "running"}); err != nil || !strings.Contains(got.Output, "QueryId") {
		t.Errorf("running: %+v, %v", got, err)
	}
	if got, err = Run(ctx, cfg, Params{Op: "slow_queries", SinceMinutes: 10080, State: "any", Limit: 3}); err != nil || got.Rows != 3 {
		t.Errorf("slow_queries: %+v, %v", got, err)
	}
	if got, err = Run(ctx, cfg, Params{Op: "profile_list", Limit: 5}); err != nil || got.Output == "" {
		t.Errorf("profile_list: %+v, %v", got, err)
	}
	// RunRedacted masks the cells of the TSV outputs and the strings of the summary.
	masked, err := RunRedacted(ctx, cfg, Params{Op: "cluster", Component: "frontends"}, func(s string) string { return strings.ReplaceAll(s, "LEADER", "[REDACTED]") })
	if err != nil || strings.Contains(masked.Output, "LEADER") || !strings.Contains(masked.Output, "[REDACTED]") {
		t.Errorf("masked cluster: %+v, %v", masked, err)
	}
	if _, err := Run(ctx, Config{Credential: looseFile, Address: address}, Params{Op: "cluster"}); err == nil || !strings.Contains(err.Error(), "mode 0600") {
		t.Errorf("a 0644 credential file: %v", err)
	}
	if _, err := Run(ctx, cfg, Params{Op: "profile_run", SQL: "SELECT 1"}); err == nil || !strings.Contains(err.Error(), "allow_profile_run") {
		t.Errorf("profile_run: %v", err)
	}
	cfg.AllowProfileRun = true
	if got, err = Run(ctx, cfg, Params{Op: "profile_run", SQL: "SELECT count(*) FROM demo_dw.dim_user"}); err != nil || !strings.Contains(got.Output, `"result_rows":1`) {
		t.Errorf("profile_run: %+v, %v", got, err)
	}
	cfg.Timeout = time.Second
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := Run(cancelled, cfg, Params{Op: "cluster"}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

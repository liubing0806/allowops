//go:build srdr

// Package e2e runs every StarRocks/Dremio example action through the full
// chain: MCP client -> gateway binary -> agent (container) -> sudo ->
// allowops-exec -> builtin handler -> local StarRocks/Dremio.
package e2e

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/test/harness"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type credential struct {
	UserName string `json:"userName"`
	Password string `json:"password"`
}

// record is one MCP call and what came back.
type record struct {
	Action    string          `json:"action"`
	Case      string          `json:"case"`
	Kind      string          `json:"kind"` // success or reject
	Arguments map[string]any  `json:"arguments"`
	ElapsedMS int64           `json:"elapsed_ms"`
	ToolError bool            `json:"tool_error"`
	Status    string          `json:"status,omitempty"`
	JobID     string          `json:"job_id,omitempty"`
	Result    json.RawMessage `json:"result"`
	Stdout    string          `json:"stdout,omitempty"`
	Stderr    string          `json:"stderr,omitempty"`
	Reason    string          `json:"task_reason,omitempty"`
	// Server is the statement fragment looked up in the database's own query
	// record: it must be present for a success and absent for a rejection.
	Server     string `json:"server_statement,omitempty"`
	ServerSeen *bool  `json:"server_saw_statement,omitempty"`
	Pass       bool   `json:"pass"`
	Note       string `json:"note,omitempty"`
}

var reasonPattern = regexp.MustCompile(`[A-Z][A-Z_]{5,}`)

type bearer struct {
	base  http.RoundTripper
	token string
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../..")
	harness.Check(t, err)
	return root
}

func TestEndToEnd(t *testing.T) {
	ctx := context.Background()
	repo := repoRoot(t)
	statePath := os.Getenv("ALLOWOPS_SRDR_CREDENTIALS")
	if statePath == "" {
		t.Fatal("ALLOWOPS_SRDR_CREDENTIALS must name the credentials.json written by up.sh")
	}
	var creds map[string]credential
	data, err := os.ReadFile(statePath)
	harness.Check(t, err)
	harness.Check(t, json.Unmarshal(data, &creds))
	out := os.Getenv("ALLOWOPS_SRDR_RESULTS")
	if out == "" {
		out = t.TempDir()
	}
	harness.Check(t, os.MkdirAll(out, 0700))

	cat := localCatalog(t, repo)
	g := harness.NewWith(t, 1, harness.Options{Repo: repo, Catalog: cat})
	t.Cleanup(func() { g.Log(t) })
	container := startHost(t, repo, g)
	for file, key := range map[string]string{"starrocks-query.json": "sr_query", "starrocks-diag.json": "sr_diag", "dremio.json": "dremio_user"} {
		c, ok := creds[key]
		if !ok {
			t.Fatalf("credentials.json has no %s", key)
		}
		body, _ := json.Marshal(map[string]string{"username": c.UserName, "password": c.Password})
		cmd := exec.Command("docker", "exec", "-i", container, "sh", "-c", "umask 077; cat > /etc/allowops/credentials/"+file+"; chmod 0600 /etc/allowops/credentials/"+file)
		cmd.Stdin = bytes.NewReader(body)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("write credential %s: %v %s", file, err, b)
		}
	}
	hostname := waitHost(t, g, container, cat.Config.CatalogID)

	transport := bearer{base: g.HTTP.Transport, token: g.Token}
	client := sdk.NewClient(&sdk.Implementation{Name: "srdr-e2e", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: "https://" + g.Address + "/mcp", HTTPClient: &http.Client{Transport: transport, Timeout: 3 * time.Minute}, DisableStandaloneSSE: true}, nil)
	harness.Check(t, err)
	t.Cleanup(func() { _ = session.Close() })

	schemas := map[string]any{}
	total := 0
	for tool, err := range session.Tools(ctx, nil) {
		harness.Check(t, err)
		total++
		if strings.HasPrefix(tool.Name, "starrocks_") || strings.HasPrefix(tool.Name, "dremio_") {
			schemas[tool.Name] = tool.InputSchema
		}
	}
	t.Logf("tools/list returned %d tools", total)
	writeJSON(t, filepath.Join(out, "tool-schemas.json"), schemas)
	if len(schemas) != 11 {
		t.Fatalf("expected 11 StarRocks/Dremio tools, got %d: %v", len(schemas), keys(schemas))
	}

	h := &runner{t: t, session: session, host: hostname, g: g}
	startedAt := time.Now().Add(-2 * time.Second)
	srQueryID := starrocksProfileQuery(t, creds["sr_query"])
	h.bootstrapDremioJob(t)

	cases := h.cases(srQueryID)
	var records []record
	for _, c := range cases {
		rec := h.call(c)
		records = append(records, rec)
		t.Logf("%-26s %-8s %-28s pass=%v elapsed=%dms status=%s", rec.Action, rec.Kind, rec.Case, rec.Pass, rec.ElapsedMS, rec.Status)
		writeJSON(t, filepath.Join(out, "results.json"), records)
	}
	statements := append(starrocksAudit(t, startedAt), h.dremioStatements()...)
	writeJSON(t, filepath.Join(out, "server-statements.json"), statements)
	for i := range records {
		rec := &records[i]
		if rec.Server == "" {
			continue
		}
		seen := false
		for _, st := range statements {
			if strings.Contains(st, rec.Server) {
				seen = true
				break
			}
		}
		rec.ServerSeen = &seen
		if seen != (rec.Kind == "success") {
			rec.Pass = false
			rec.Note = strings.TrimSpace(rec.Note + fmt.Sprintf(" server saw %q: %v", rec.Server, seen))
		}
	}
	writeJSON(t, filepath.Join(out, "results.json"), records)
	failed := 0
	for _, rec := range records {
		if !rec.Pass {
			failed++
			t.Errorf("%s/%s (%s): unexpected outcome: %s", rec.Action, rec.Case, rec.Kind, rec.Note)
		}
	}
	t.Logf("%d calls, %d unexpected; results in %s", len(records), failed, out)
}

func keys(m map[string]any) []string {
	var k []string
	for name := range m {
		k = append(k, name)
	}
	return k
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	harness.Check(t, err)
	harness.Check(t, os.WriteFile(path, data, 0600))
}

// localCatalog copies examples/catalog and points the StarRocks/Dremio actions
// at the local compose ports. examples/ itself stays unchanged.
func localCatalog(t *testing.T, repo string) *catalog.Catalog {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "catalog")
	harness.Check(t, exec.Command("cp", "-r", filepath.Join(repo, "examples/catalog"), dir).Run())
	replaced := 0
	for pattern, pair := range map[string][2]string{"starrocks_*.yaml": {"tcp://127.0.0.1:9030", "tcp://127.0.0.1:29030"}, "dremio_*.yaml": {"http://127.0.0.1:9047", "http://127.0.0.1:29047"}} {
		files, err := filepath.Glob(filepath.Join(dir, "actions", pattern))
		harness.Check(t, err)
		for _, file := range files {
			raw, err := os.ReadFile(file)
			harness.Check(t, err)
			text := string(raw)
			if !strings.Contains(text, pair[0]) {
				t.Fatalf("%s does not contain %s", file, pair[0])
			}
			harness.Check(t, os.WriteFile(file, []byte(strings.ReplaceAll(text, pair[0], pair[1])), 0644))
			replaced++
		}
	}
	if replaced != 11 {
		t.Fatalf("rewrote %d example files, want 11", replaced)
	}
	c, err := catalog.Load(dir)
	harness.Check(t, err)
	return c
}

// startHost builds the agent image and starts it on the host network.
func startHost(t *testing.T, repo string, g *harness.Gateway) string {
	t.Helper()
	ctxDir := t.TempDir()
	for _, name := range []string{"allowops-agent", "allowops-exec"} {
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w -X main.version=0.1.0", "-o", filepath.Join(ctxDir, name), "./cmd/"+name)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOAMD64=v1")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v %s", name, err, b)
		}
	}
	copyFile := func(src, dst string) {
		raw, err := os.ReadFile(src)
		harness.Check(t, err)
		harness.Check(t, os.WriteFile(filepath.Join(ctxDir, dst), raw, 0644))
	}
	here := filepath.Join(repo, "test/starrocks-dremio/e2e")
	copyFile(filepath.Join(here, "Dockerfile"), "Dockerfile")
	copyFile(filepath.Join(here, "entrypoint.sh"), "entrypoint.sh")
	copyFile(filepath.Join(repo, "deploy/packaging/allowops.sudoers"), "allowops.sudoers")
	copyFile(filepath.Join(g.Dir, "keys", "catalog.pem"), "catalog.pub.pem")
	harness.Check(t, os.WriteFile(filepath.Join(ctxDir, "agent.yaml"), []byte(fmt.Sprintf("upstream: https://%s\nca_pin: %s\nreported_labels:\n  environment: srdr\n", g.Address, g.Pin)), 0644))
	harness.Check(t, os.WriteFile(filepath.Join(ctxDir, "join.token"), []byte(g.JoinToken+"\n"), 0600))
	suffix := fmt.Sprintf("%d", time.Now().UnixNano()%1e9)
	image, name := "allowops-srdr-e2e-host:"+suffix, "allowops-srdr-e2e-host-"+suffix
	if b, err := exec.Command("docker", "build", "--network", "host", "--build-arg", "HTTP_PROXY", "--build-arg", "HTTPS_PROXY", "-q", "-t", image, ctxDir).CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v %s", err, b)
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", name).Run()
		_ = exec.Command("docker", "rmi", image).Run()
	})
	if b, err := exec.Command("docker", "run", "-d", "--network", "host", "--name", name, image).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v %s", err, b)
	}
	return name
}

func waitHost(t *testing.T, g *harness.Gateway, container, catalogID string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		var hostname string
		err := g.DB.Pool.QueryRow(context.Background(), "SELECT h.hostname FROM hosts h JOIN host_catalog_reports r USING(host_id) WHERE h.connection_id IS NOT NULL AND r.loaded AND r.catalog_id=$1", catalogID).Scan(&hostname)
		if err == nil {
			_, err = g.DB.Pool.Exec(context.Background(), `UPDATE hosts SET authorization_labels='{"env":"srdr"}'`)
			harness.Check(t, err)
			return hostname
		}
		time.Sleep(500 * time.Millisecond)
	}
	logs, _ := exec.Command("docker", "logs", container).CombinedOutput()
	t.Fatalf("host did not connect and load the catalog; container log:\n%s", logs)
	return ""
}

// starrocksProfileQuery runs one query with profiling on and returns its id.
func starrocksProfileQuery(t *testing.T, c credential) string {
	t.Helper()
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net, cfg.Addr, cfg.DBName = c.UserName, c.Password, "tcp", "127.0.0.1:29030", "demo_dw"
	connector, err := mysql.NewConnector(cfg)
	harness.Check(t, err)
	db := sql.OpenDB(connector)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	conn, err := db.Conn(ctx)
	harness.Check(t, err)
	defer conn.Close()
	_, err = conn.ExecContext(ctx, "SET enable_profile = true")
	harness.Check(t, err)
	rows, err := conn.QueryContext(ctx, "SELECT store_id, count(*) AS c FROM demo_dw.fact_orders GROUP BY store_id ORDER BY c DESC LIMIT 5")
	harness.Check(t, err)
	for rows.Next() {
	}
	harness.Check(t, rows.Close())
	var id string
	harness.Check(t, conn.QueryRowContext(ctx, "SELECT last_query_id()").Scan(&id))
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		var profile sql.NullString
		if err := conn.QueryRowContext(ctx, "SELECT get_query_profile(?)", id).Scan(&profile); err == nil && profile.Valid && len(profile.String) > 100 {
			return id
		}
	}
	t.Fatalf("profile for %s was not registered within 30s", id)
	return ""
}

type runner struct {
	g        *harness.Gateway
	t        *testing.T
	session  *sdk.ClientSession
	host     string
	dremioID string
}

type testCase struct {
	action string
	name   string
	kind   string // success or reject
	params map[string]any
	// contains is a substring that must appear in stdout (success) or in the error/stderr text (reject).
	contains string
	// server is a statement fragment: StarRocks FE audit log and Dremio job list must contain it
	// for a success and must not contain it for a rejection.
	server string
	// absent must not appear in stdout (redaction); truncated requires the result summary to report truncation.
	absent    string
	truncated bool
}

func (h *runner) bootstrapDremioJob(t *testing.T) {
	t.Helper()
	marker := "SELECT city, count(*) AS n FROM \"starrocks\".demo_dw.dim_user GROUP BY city ORDER BY n DESC"
	rec := h.call(testCase{action: "dremio_query_readonly", name: "bootstrap (profile target)", kind: "success", params: map[string]any{"sql": marker}})
	if !rec.Pass {
		t.Fatalf("cannot create a Dremio job for the profile calls: %s", rec.Note)
	}
	jobs := h.call(testCase{action: "dremio_jobs_recent", name: "bootstrap (find job id)", kind: "success", params: map[string]any{"since": "10m", "limit": 50}})
	for _, line := range strings.Split(jobs.Stdout, "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) >= 12 && strings.Contains(fields[len(fields)-1], "GROUP BY city ORDER BY n DESC") {
			h.dremioID = fields[0]
			return
		}
	}
	t.Fatalf("job for the bootstrap query not found in dremio_jobs_recent output:\n%s", jobs.Stdout)
}

func (h *runner) cases(srQueryID string) []testCase {
	const nonUUID = "not-a-query-id"
	sr := func(sqlText string) map[string]any { return map[string]any{"sql": sqlText, "database": "demo_dw"} }
	dr := func(sqlText string) map[string]any { return map[string]any{"sql": sqlText} }
	// Denied statements carry the literal p6_e2e_denied / 987654321 so that a lookup in the
	// database's own statement record cannot match another session's traffic.
	return []testCase{
		{action: "starrocks_query_readonly", name: "select count", kind: "success", params: sr("SELECT count(*) FROM fact_orders"), contains: "500000", server: "SELECT count(*) FROM fact_orders"},
		{action: "starrocks_query_readonly", name: "show tables", kind: "success", params: sr("SHOW TABLES"), contains: "fact_orders", server: "SHOW TABLES"},
		{action: "starrocks_query_readonly", name: "DROP TABLE", kind: "reject", params: sr("DROP TABLE p6_e2e_denied"), server: "DROP TABLE p6_e2e_denied"},
		{action: "starrocks_query_readonly", name: "INSERT", kind: "reject", params: sr("INSERT INTO p6_e2e_denied VALUES (987654321)"), server: "INSERT INTO p6_e2e_denied"},
		{action: "starrocks_query_readonly", name: "row limit (max_rows 200)", kind: "success", params: sr("SELECT order_id FROM fact_orders ORDER BY order_id LIMIT 1000"), contains: "\n1\n", truncated: true, server: "ORDER BY order_id LIMIT 1000"},
		{action: "starrocks_query_readonly", name: "redaction", kind: "success", params: sr("SELECT 'password=hunter2-p6' AS v"), contains: "REDACTED", absent: "hunter2-p6", server: "SELECT 'password=hunter2-p6'"},
		{action: "starrocks_explain", name: "explain select", kind: "success", params: sr("EXPLAIN SELECT count(*) FROM fact_orders"), contains: "OlapScanNode", server: "EXPLAIN SELECT count(*) FROM fact_orders"},
		{action: "starrocks_explain", name: "EXPLAIN ANALYZE", kind: "reject", params: sr("EXPLAIN ANALYZE SELECT count(*) FROM fact_orders WHERE order_id = 987654321"), server: "EXPLAIN ANALYZE SELECT count(*) FROM fact_orders WHERE order_id = 987654321"},
		{action: "starrocks_explain", name: "not an EXPLAIN", kind: "reject", params: sr("SELECT 1")},
		{action: "starrocks_cluster_status", name: "op=cluster all", kind: "success", params: map[string]any{"op": "cluster"}, contains: "# frontends", server: "SHOW FRONTENDS"},
		{action: "starrocks_cluster_status", name: "op=running", kind: "success", params: map[string]any{"op": "running"}, server: "/current_queries"},
		{action: "starrocks_cluster_status", name: "unknown component", kind: "reject", params: map[string]any{"op": "cluster", "component": "frontends; DROP"}},
		{action: "starrocks_slow_queries", name: "slow_queries", kind: "success", params: map[string]any{"op": "slow_queries", "since_minutes": 10080, "limit": 5}, contains: "query_id", server: "starrocks_audit_tbl__"},
		{action: "starrocks_slow_queries", name: "state injection", kind: "reject", params: map[string]any{"op": "slow_queries", "state": "OK' OR '1'='1"}},
		{action: "starrocks_profile_list", name: "profile_list", kind: "success", params: map[string]any{"op": "profile_list", "limit": 5}, contains: srQueryID, server: "SHOW PROFILELIST"},
		{action: "starrocks_profile_list", name: "limit over max", kind: "reject", params: map[string]any{"op": "profile_list", "limit": 100000}},
		{action: "starrocks_profile_summary", name: "profile_summary", kind: "success", params: map[string]any{"op": "profile_summary", "query_id": srQueryID, "top_n": 5}, contains: "top_operators", server: "get_query_profile('" + srQueryID + "')"},
		{action: "starrocks_profile_summary", name: "non-UUID query_id", kind: "reject", params: map[string]any{"op": "profile_summary", "query_id": nonUUID}},
		{action: "starrocks_profile_summary", name: "quote in query_id", kind: "reject", params: map[string]any{"op": "profile_summary", "query_id": srQueryID + "' OR '1'='1"}, server: srQueryID + "' OR"},
		{action: "dremio_query_readonly", name: "select count", kind: "success", params: dr("SELECT count(*) AS n FROM \"starrocks\".demo_dw.dim_user"), contains: "10000", server: "SELECT count(*) AS n FROM"},
		{action: "dremio_query_readonly", name: "CREATE TABLE", kind: "reject", params: dr("CREATE TABLE \"starrocks-scratch\".scratch.p6_e2e_denied AS SELECT 1"), server: "p6_e2e_denied AS SELECT"},
		{action: "dremio_query_readonly", name: "DROP TABLE", kind: "reject", params: dr("DROP TABLE \"starrocks-scratch\".scratch.p6_e2e_denied"), server: "DROP TABLE \"starrocks-scratch\".scratch.p6_e2e_denied"},
		{action: "dremio_query_readonly", name: "redaction", kind: "success", params: dr("SELECT 'password=hunter2-p6' AS v"), contains: "REDACTED", absent: "hunter2-p6", server: "SELECT 'password=hunter2-p6'"},
		{action: "dremio_explain", name: "explain plan", kind: "success", params: dr("EXPLAIN PLAN FOR SELECT count(*) FROM \"starrocks\".demo_dw.dim_user"), contains: "Screen", server: "EXPLAIN PLAN FOR SELECT count(*)"},
		{action: "dremio_explain", name: "not an EXPLAIN", kind: "reject", params: dr("SELECT 1")},
		{action: "dremio_explain", name: "EXPLAIN of a write", kind: "reject", params: dr("EXPLAIN PLAN FOR INSERT INTO \"starrocks-scratch\".scratch.p6_e2e_denied VALUES (987654321)"), server: "INSERT INTO \"starrocks-scratch\".scratch.p6_e2e_denied"},
		{action: "dremio_nodes", name: "nodes", kind: "success", params: map[string]any{}, contains: "sys.nodes", server: "sys.nodes"},
		{action: "dremio_nodes", name: "unknown op", kind: "reject", params: map[string]any{"op": "jobs"}},
		{action: "dremio_jobs_recent", name: "jobs since 1h", kind: "success", params: map[string]any{"since": "1h", "limit": 5}, contains: "id\tstate"},
		{action: "dremio_jobs_recent", name: "user injection", kind: "reject", params: map[string]any{"user": "x' OR '1'='1"}},
		{action: "dremio_job_profile", name: "job_profile", kind: "success", params: map[string]any{"job_id": h.dremioID, "top_n": 5}, contains: h.dremioID},
		{action: "dremio_job_profile", name: "non-UUID job_id", kind: "reject", params: map[string]any{"job_id": nonUUID}},
	}
}

// call runs one action on the host, reads its full stdout and stderr, and
// judges the outcome against the case's kind.
func (h *runner) call(c testCase) record {
	t := h.t
	t.Helper()
	args := map[string]any{"targets": map[string]any{"hosts": []string{h.host}}, "reason": "StarRocks/Dremio end-to-end verification", "wait_seconds": 60, "params": c.params}
	rec := record{Action: c.action, Case: c.name, Kind: c.kind, Arguments: map[string]any{"params": c.params}, Server: c.server}
	start := time.Now()
	res, err := h.session.CallTool(context.Background(), &sdk.CallToolParams{Name: c.action, Arguments: args})
	rec.ElapsedMS = time.Since(start).Milliseconds()
	if err != nil {
		rec.ToolError = true
		rec.Note = "protocol error: " + err.Error()
		rec.Stderr = err.Error()
		rec.Pass = c.kind == "reject" // a protocol-level refusal also counts as rejected
		return rec
	}
	raw, _ := json.Marshal(res.StructuredContent)
	rec.Result = raw
	rec.ToolError = res.IsError
	var summary map[string]any
	_ = json.Unmarshal(raw, &summary)
	if id, ok := summary["job_id"].(string); ok {
		rec.JobID = id
		rec.Status, _ = summary["status"].(string)
		var result []byte
		if err := h.g.DB.Pool.QueryRow(context.Background(), "SELECT result FROM tasks WHERE job_id=$1", rec.JobID).Scan(&result); err == nil {
			rec.Reason = reasonPattern.FindString(string(result))
		}
		rec.Stdout = h.output(rec.JobID, "stdout")
		rec.Stderr = h.output(rec.JobID, "stderr")
	}
	if res.IsError && rec.JobID == "" {
		var text []string
		for _, content := range res.Content {
			if tc, ok := content.(*sdk.TextContent); ok {
				text = append(text, tc.Text)
			}
		}
		rec.Stderr = strings.Join(text, "\n")
	}
	succeeded := !res.IsError && rec.JobID != "" && strings.EqualFold(rec.Status, "succeeded")
	switch c.kind {
	case "success":
		rec.Pass = succeeded && (c.contains == "" || strings.Contains(rec.Stdout, c.contains)) &&
			(c.absent == "" || !strings.Contains(rec.Stdout, c.absent)) &&
			(!c.truncated || strings.Contains(string(raw), `"truncated":true`))
		if !rec.Pass {
			rec.Note = fmt.Sprintf("status=%q tool_error=%v wanted stdout containing %q, without %q, truncated=%v", rec.Status, res.IsError, c.contains, c.absent, c.truncated)
		}
	case "reject":
		rec.Pass = !succeeded
		if !rec.Pass {
			rec.Note = "call succeeded but was expected to be rejected"
		}
	}
	return rec
}

// output reads a task's complete stream through jobs_get pages.
func (h *runner) output(job, stream string) string {
	var buf []byte
	offset := uint64(0)
	for i := 0; i < 64; i++ {
		res, err := h.session.CallTool(context.Background(), &sdk.CallToolParams{Name: "jobs_get", Arguments: map[string]any{"job_id": job, "host": h.host, "stream": stream, "wait_seconds": 10, "offset": offset}})
		if err != nil || res.IsError {
			return string(buf)
		}
		var page struct {
			Data string `json:"data_base64"`
			Next uint64 `json:"next_offset"`
			EOF  bool   `json:"eof"`
		}
		raw, _ := json.Marshal(res.StructuredContent)
		if json.Unmarshal(raw, &page) != nil {
			return string(buf)
		}
		decoded, _ := base64.StdEncoding.DecodeString(page.Data)
		buf = append(buf, decoded...)
		if page.EOF || page.Next <= offset {
			break
		}
		offset = page.Next
	}
	return string(buf)
}

// starrocksAudit returns the statements the FE recorded for the allowops accounts since start.
func starrocksAudit(t *testing.T, since time.Time) []string {
	t.Helper()
	container := os.Getenv("ALLOWOPS_SRDR_FE_CONTAINER")
	if container == "" {
		container = "allowops-srdr-sr-fe"
	}
	raw, err := exec.Command("docker", "exec", container, "sh", "-c", "grep -a 'User=allowops_' /opt/starrocks/fe/log/fe.audit.log").Output()
	harness.Check(t, err)
	var statements []string
	for _, line := range strings.Split(string(raw), "\n") {
		ts := regexp.MustCompile(`\|Timestamp=(\d+)\|`).FindStringSubmatch(line)
		if ts == nil {
			continue
		}
		var ms int64
		fmt.Sscan(ts[1], &ms)
		if ms < since.UnixMilli() {
			continue
		}
		if i := strings.Index(line, "|Stmt="); i >= 0 {
			stmt := line[i+len("|Stmt="):]
			if j := strings.Index(stmt, "|Digest="); j >= 0 {
				stmt = stmt[:j]
			}
			statements = append(statements, "starrocks: "+stmt)
		}
	}
	return statements
}

// dremioStatements lists the statements of recent Dremio jobs through dremio_jobs_recent.
func (h *runner) dremioStatements() []string {
	rec := h.call(testCase{action: "dremio_jobs_recent", name: "evidence (all recent jobs)", kind: "success", params: map[string]any{"since": "30m", "limit": 100}})
	var statements []string
	for i, line := range strings.Split(rec.Stdout, "\n") {
		fields := strings.Split(line, "\t")
		if i == 0 || len(fields) < 12 {
			continue
		}
		statements = append(statements, "dremio: "+fields[len(fields)-1])
	}
	return statements
}

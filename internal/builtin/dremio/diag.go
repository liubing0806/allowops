package dremio

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/liubing0806/allowops/internal/builtin"
	"github.com/liubing0806/allowops/internal/builtin/credfile"
)

// The dremio_diag builtin runs fixed requests only: sys tables through the SQL
// API, the job list and the job profile through the REST API of the Dremio
// user interface. The caller selects an op and its parameters; no part of a
// request comes from the caller except values that were checked against a fixed
// pattern or range.

// Ops of dremio_diag.
const (
	OpNodes      = "nodes"
	OpJobs       = "jobs"
	OpJob        = "job"
	OpJobProfile = "job_profile"
	OpReflection = "reflections"
)

// Ops lists the values of the op parameter.
var Ops = []string{OpNodes, OpJobs, OpJob, OpJobProfile, OpReflection}

// JobStates are the values of the state parameter that the job list accepts as
// the job state filter (jst).
var JobStates = []string{"RUNNING", "COMPLETED", "FAILED", "CANCELED"}

const (
	// DefaultMaxProfileBytes is the largest profile JSON that is read. The
	// document is parsed in memory, so the limit also bounds the memory of one call.
	DefaultMaxProfileBytes = builtin.DefaultDremioMaxProfileBytes
	// MaxSince is the longest time window of the jobs op.
	MaxSince = 168 * time.Hour
	// DefaultJobsLimit and DefaultTopOperators are used when the parameter is absent.
	DefaultJobsLimit    = 20
	DefaultTopOperators = 10
	// maxQueryRunes cuts the statement text in the job list.
	maxQueryRunes = 200
	// maxZipBytes bounds the compressed profile that is downloaded.
	maxZipBytes int64 = 16 << 20
)

// userPattern admits the user names that go into the job list filter: no quote,
// parenthesis, semicolon or comparison character.
var userPattern = regexp.MustCompile(`^[A-Za-z0-9._@][A-Za-z0-9._@-]{0,127}$`)

// diagJobIDPattern is the format of a Dremio job id, which is a UUID. Only a value
// of this format is put into a request path.
var diagJobIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// DiagConfig is trusted catalog configuration. Zero limits select the
// defaults, which are also the maximum.
type DiagConfig struct {
	Credential string `yaml:"credential" json:"credential"`
	URL        string `yaml:"url" json:"url"`
	// MaxRows limits the rows of the sys tables and the entries of the job list.
	MaxRows int `yaml:"max_rows" json:"max_rows"`
	// MaxBytes limits the text of one result, a profile summary included.
	MaxBytes int64         `yaml:"max_bytes" json:"max_bytes"`
	Timeout  time.Duration `yaml:"timeout" json:"timeout"`
	// MaxProfileBytes limits the unzipped profile JSON and, with it, the zip.
	MaxProfileBytes int64 `yaml:"max_profile_bytes" json:"max_profile_bytes"`
	// Ops is a nonempty subset of Ops; nil allows all of them.
	Ops []string `yaml:"ops" json:"ops"`
}

// DiagParams are the caller's parameters. Which of them an op accepts is
// checked by Validate; pointers tell an absent parameter from a zero value.
type DiagParams struct {
	Op          string
	JobID       string
	Since       *time.Duration
	MinDuration *time.Duration
	State       string
	User        string
	Limit       *int
	TopN        *int
}

func (c DiagConfig) Validate() error {
	base := Config{Credential: c.Credential, URL: c.URL, MaxRows: c.MaxRows, MaxBytes: c.MaxBytes, Timeout: c.Timeout}
	if err := base.Validate(); err != nil {
		return err
	}
	if c.MaxProfileBytes < 0 || c.MaxProfileBytes > DefaultMaxProfileBytes {
		return fmt.Errorf("max_profile_bytes must be between 0 and %d", DefaultMaxProfileBytes)
	}
	if c.Ops != nil && len(c.Ops) == 0 {
		return fmt.Errorf("ops must be a nonempty subset of: %s", strings.Join(Ops, ", "))
	}
	for _, op := range c.Ops {
		if !slices.Contains(Ops, op) {
			return fmt.Errorf("ops may only contain: %s", strings.Join(Ops, ", "))
		}
	}
	return nil
}

func (c DiagConfig) normalized() DiagConfig {
	base := Config{MaxRows: c.MaxRows, MaxBytes: c.MaxBytes, Timeout: c.Timeout}.normalized()
	c.MaxRows, c.MaxBytes, c.Timeout = base.MaxRows, base.MaxBytes, base.Timeout
	if c.MaxProfileBytes == 0 {
		c.MaxProfileBytes = DefaultMaxProfileBytes
	}
	return c
}

// Validate checks the parameters of the op. Parameters that belong to another
// op are refused, so that a call states what it asks for.
func (p DiagParams) Validate(maxRows int) error {
	given := map[string]bool{
		"job_id": p.JobID != "", "since": p.Since != nil, "min_duration": p.MinDuration != nil,
		"state": p.State != "", "user": p.User != "", "limit": p.Limit != nil, "top_n": p.TopN != nil,
	}
	var allowed []string
	switch p.Op {
	case OpNodes, OpReflection:
	case OpJobs:
		allowed = []string{"since", "min_duration", "state", "user", "limit"}
	case OpJob:
		allowed = []string{"job_id"}
	case OpJobProfile:
		allowed = []string{"job_id", "top_n"}
	default:
		return fmt.Errorf("op must be one of: %s", strings.Join(Ops, ", "))
	}
	for _, name := range []string{"job_id", "since", "min_duration", "state", "user", "limit", "top_n"} {
		if given[name] && !containsFold(allowed, name) {
			return fmt.Errorf("op %s does not take parameter %s", p.Op, name)
		}
	}
	if (p.Op == OpJob || p.Op == OpJobProfile) && !diagJobIDPattern.MatchString(p.JobID) {
		return errors.New("job_id must be a job id of the form 8-4-4-4-12 hexadecimal digits")
	}
	if p.State != "" && !containsFold(JobStates, p.State) {
		return fmt.Errorf("state must be one of: %s", strings.Join(JobStates, ", "))
	}
	if p.User != "" && !userPattern.MatchString(p.User) {
		return errors.New("user may contain only letters, digits and . _ @ -, must not start with -, and has at most 128 characters")
	}
	if p.Since != nil && (*p.Since <= 0 || *p.Since > MaxSince) {
		return fmt.Errorf("since must be between 1ns and %s", MaxSince)
	}
	if p.MinDuration != nil && (*p.MinDuration < 0 || *p.MinDuration > MaxSince) {
		return fmt.Errorf("min_duration must be between 0 and %s", MaxSince)
	}
	if p.Limit != nil && (*p.Limit < 1 || *p.Limit > maxRows) {
		return fmt.Errorf("limit must be between 1 and %d", maxRows)
	}
	if p.TopN != nil && (*p.TopN < 1 || *p.TopN > maxTopOperators) {
		return fmt.Errorf("top_n must be between 1 and %d", maxTopOperators)
	}
	return nil
}

// RunDiag is RunDiagRedacted without a mask.
func RunDiag(ctx context.Context, cfg DiagConfig, p DiagParams) (Result, error) {
	return RunDiagRedacted(ctx, cfg, p, nil)
}

// RunDiagRedacted applies the caller's policy to every string that came from
// the server. The parameters are validated before the credential file is read
// and before any request is sent.
func RunDiagRedacted(ctx context.Context, cfg DiagConfig, p DiagParams, mask func(string) string) (Result, error) {
	if err := cfg.Validate(); err != nil {
		return Result{}, err
	}
	cfg = cfg.normalized()
	if err := p.Validate(cfg.MaxRows); err != nil {
		return Result{}, err
	}
	if cfg.Ops != nil && !slices.Contains(cfg.Ops, p.Op) {
		return Result{}, fmt.Errorf("ops allows only: %s", strings.Join(cfg.Ops, ", "))
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	cred, err := readCredential(cfg.Credential)
	if err != nil {
		return Result{}, err
	}
	return runDiag(ctx, cfg, p, cred, mask)
}

func identity(s string) string { return s }

// runDiag receives validated parameters and normalized limits.
func runDiag(ctx context.Context, cfg DiagConfig, p DiagParams, cred credfile.Credential, mask func(string) string) (Result, error) {
	if mask == nil {
		mask = identity
	}
	base, err := parseURL(cfg.URL)
	if err != nil {
		return Result{}, err
	}
	c := newClient(base)
	defer c.close()
	token, err := c.login(ctx, cred)
	if err != nil {
		return Result{}, err
	}
	// The session lasts 720 hours, so it is closed on every path.
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), cleanupTimeout)
		defer done()
		_ = c.logout(cleanup, token)
	}()
	query := Config{MaxRows: cfg.MaxRows, MaxBytes: cfg.MaxBytes}
	switch p.Op {
	case OpNodes:
		return diagNodes(ctx, c, token, query, mask)
	case OpReflection:
		return c.sysTable(ctx, token, "SELECT * FROM sys.reflections", query, mask)
	case OpJobs:
		return diagJobs(ctx, c, token, cfg, p, mask)
	case OpJob:
		return diagJob(ctx, c, token, cfg, p.JobID, mask)
	default:
		return diagJobProfile(ctx, c, token, cfg, p, mask)
	}
}

// sysTable runs one fixed statement as a job and returns its first page. A job
// that has not ended when the call ends is cancelled on a deadline of its own.
func (c *client) sysTable(ctx context.Context, token, statement string, cfg Config, mask func(string) string) (Result, error) {
	id, err := c.submit(ctx, token, statement)
	if err != nil {
		return Result{}, err
	}
	finished := false
	defer func() {
		if !finished {
			cleanup, done := context.WithTimeout(context.Background(), cleanupTimeout)
			defer done()
			_ = c.cancel(cleanup, token, id)
		}
	}()
	state, message, err := c.wait(ctx, token, id)
	if err != nil {
		return Result{}, err
	}
	finished = true
	if state != stateCompleted {
		return Result{}, jobError(state, message)
	}
	return c.fetch(ctx, token, id, cfg, mask)
}

// diagNodes returns sys.nodes and sys.memory, each with a title line. The
// second table gets what the first one left of the byte limit.
func diagNodes(ctx context.Context, c *client, token string, cfg Config, mask func(string) string) (Result, error) {
	const title1, title2 = "# sys.nodes\n", "# sys.memory\n"
	first, err := c.sysTable(ctx, token, "SELECT * FROM sys.nodes", Config{MaxRows: cfg.MaxRows, MaxBytes: cfg.MaxBytes - int64(len(title1))}, mask)
	if err != nil {
		return Result{}, err
	}
	out := title1 + first.Output
	result := Result{Rows: first.Rows, Truncated: first.Truncated}
	left := cfg.MaxBytes - int64(len(out)) - int64(len(title2))
	if left < 64 {
		result.Output = out
		result.Truncated = true
		return result, nil
	}
	second, err := c.sysTable(ctx, token, "SELECT * FROM sys.memory", Config{MaxRows: cfg.MaxRows, MaxBytes: left}, mask)
	if err != nil {
		return Result{}, err
	}
	result.Output = out + title2 + second.Output
	result.Rows += second.Rows
	result.Truncated = result.Truncated || second.Truncated
	return result, nil
}

// jobsFilter builds the filter of the job list from checked values. The keys
// are the ones that the local environment accepted: jst (state), usr (user),
// dur (duration in milliseconds) and st (start time in epoch milliseconds).
func jobsFilter(p DiagParams, now time.Time) string {
	since := time.Hour
	if p.Since != nil {
		since = *p.Since
	}
	terms := []string{"st=ge=" + strconv.FormatInt(now.Add(-since).UnixMilli(), 10)}
	if p.State != "" {
		terms = append(terms, `jst=="`+strings.ToUpper(p.State)+`"`)
	}
	if p.User != "" {
		terms = append(terms, `usr=="`+p.User+`"`)
	}
	if p.MinDuration != nil && *p.MinDuration > 0 {
		terms = append(terms, "dur=ge="+strconv.FormatInt(p.MinDuration.Milliseconds(), 10))
	}
	return "(" + strings.Join(terms, ";") + ")"
}

type listedJob struct {
	ID            string  `json:"id"`
	QueryType     string  `json:"queryType"`
	QueryText     string  `json:"queryText"`
	State         string  `json:"state"`
	User          string  `json:"user"`
	Queue         string  `json:"wlmQueue"`
	StartTime     int64   `json:"startTime"`
	Duration      int64   `json:"duration"`
	RowsScanned   int64   `json:"rowsScanned"`
	OutputRecords int64   `json:"outputRecords"`
	Accelerated   bool    `json:"accelerated"`
	Spilled       bool    `json:"spilled"`
	Cost          float64 `json:"plannerEstimatedCost"`
}

var jobColumns = []string{"id", "state", "user", "query_type", "queue", "start_time", "duration_ms", "rows_scanned", "output_records", "accelerated", "spilled", "query"}

// diagJobs lists jobs through GET /apiv2/jobs-listing/v1.0, because Dremio 24.1
// has no sys.jobs_recent and sys.jobs holds the running jobs only. With a
// minimum duration the list is sorted by duration, otherwise by start time,
// both from the largest value.
func diagJobs(ctx context.Context, c *client, token string, cfg DiagConfig, p DiagParams, mask func(string) string) (Result, error) {
	limit := DefaultJobsLimit
	if p.Limit != nil {
		limit = *p.Limit
	}
	limit = min(limit, cfg.MaxRows)
	sortKey := "st"
	if p.MinDuration != nil && *p.MinDuration > 0 {
		sortKey = "dur"
	}
	// One extra entry shows whether the list has more than limit.
	path := "/apiv2/jobs-listing/v1.0?" + url.Values{
		"limit": {strconv.Itoa(limit + 1)}, "offset": {"0"}, "sort": {sortKey}, "order": {"DESCENDING"}, "filter": {jobsFilter(p, time.Now())},
	}.Encode()
	data, err := c.do(ctx, "jobs", http.MethodGet, path, token, nil, maxResultBody)
	if err != nil {
		return Result{}, err
	}
	var reply struct {
		Jobs []listedJob `json:"jobs"`
	}
	if json.Unmarshal(data, &reply) != nil {
		return Result{}, invalidResponse("jobs")
	}
	truncated := len(reply.Jobs) > limit
	if truncated {
		reply.Jobs = reply.Jobs[:limit]
	}
	rows := make([][]sql.NullString, len(reply.Jobs))
	for i, j := range reply.Jobs {
		cells := []string{
			j.ID, j.State, j.User, j.QueryType, j.Queue, time.UnixMilli(j.StartTime).UTC().Format(time.RFC3339),
			strconv.FormatInt(j.Duration, 10), strconv.FormatInt(j.RowsScanned, 10), strconv.FormatInt(j.OutputRecords, 10),
			strconv.FormatBool(j.Accelerated), strconv.FormatBool(j.Spilled), truncateRunes(oneLine(j.QueryText), maxQueryRunes),
		}
		rows[i] = make([]sql.NullString, len(cells))
		for k, cell := range cells {
			rows[i][k] = sql.NullString{String: cell, Valid: true}
		}
	}
	return encode(jobColumns, rows, truncated, cfg.MaxBytes, mask)
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// diagJob returns the status of one job from GET /api/v3/job/{id}.
func diagJob(ctx context.Context, c *client, token string, cfg DiagConfig, id string, mask func(string) string) (Result, error) {
	data, err := c.do(ctx, "job", http.MethodGet, "/api/v3/job/"+id, token, nil, maxControlBody)
	if err != nil {
		return Result{}, err
	}
	var job struct {
		JobState           string `json:"jobState"`
		RowCount           int64  `json:"rowCount"`
		ErrorMessage       string `json:"errorMessage"`
		StartedAt          string `json:"startedAt"`
		EndedAt            string `json:"endedAt"`
		QueryType          string `json:"queryType"`
		QueueName          string `json:"queueName"`
		CancellationReason string `json:"cancellationReason"`
	}
	if json.Unmarshal(data, &job) != nil || job.JobState == "" {
		return Result{}, invalidResponse("job")
	}
	out := map[string]any{
		"job_id": id, "state": job.JobState, "query_type": mask(job.QueryType), "queue": mask(job.QueueName),
		"started_at": job.StartedAt, "ended_at": job.EndedAt, "row_count": job.RowCount,
	}
	if started, err := time.Parse(time.RFC3339Nano, job.StartedAt); err == nil {
		if ended, err := time.Parse(time.RFC3339Nano, job.EndedAt); err == nil && ended.After(started) {
			out["duration_ms"] = ended.Sub(started).Milliseconds()
		}
	}
	if job.ErrorMessage != "" {
		line, _, _ := strings.Cut(job.ErrorMessage, "\n")
		out["error"] = mask(truncateRunes(line, maxErrorRunes))
		out["error_category"] = errorCategory(job.ErrorMessage)
	}
	if job.CancellationReason != "" {
		out["cancellation_reason"] = mask(truncateRunes(job.CancellationReason, maxErrorRunes))
	}
	text, err := json.Marshal(out)
	if err != nil || int64(len(text)+1) > cfg.MaxBytes {
		return Result{}, errors.New("dremio job result exceeds max_bytes")
	}
	return Result{Output: string(text) + "\n", Rows: 1}, nil
}

// downloadProfile fetches the zip of POST /apiv2/support/{id}/download. The id
// has the job id format, so it cannot change the path.
func (c *client) downloadProfile(ctx context.Context, token, id string, limit int64) ([]byte, error) {
	return c.do(ctx, "profile", http.MethodPost, "/apiv2/support/"+id+"/download", token, map[string]string{}, limit)
}

func diagJobProfile(ctx context.Context, c *client, token string, cfg DiagConfig, p DiagParams, mask func(string) string) (Result, error) {
	zipData, err := c.downloadProfile(ctx, token, p.JobID, min(maxZipBytes, cfg.MaxProfileBytes))
	if err != nil {
		return Result{}, err
	}
	profile, err := extractProfile(zipData, cfg.MaxProfileBytes)
	if err != nil {
		return Result{}, err
	}
	top := DefaultTopOperators
	if p.TopN != nil {
		top = *p.TopN
	}
	summary, err := summarize(p.JobID, profile, top, mask)
	if err != nil {
		return Result{}, err
	}
	text, truncated := fitSummary(summary, cfg.MaxBytes)
	return Result{Output: string(text) + "\n", Rows: 1, Truncated: truncated}, nil
}

// fitSummary marshals the summary within maxBytes. It drops the parts that
// matter least first: planning phases, pushdown statements, then operators from
// the end of the ranking. The hits stay.
func fitSummary(s Summary, maxBytes int64) ([]byte, bool) {
	truncated := false
	for {
		text, err := json.Marshal(s)
		if err == nil && int64(len(text)+1) <= maxBytes {
			return text, truncated
		}
		truncated = true
		switch {
		case len(s.PlanningTop) > 0:
			s.PlanningTop = nil
		case len(s.PushdownSQL) > 0:
			s.PushdownSQL = s.PushdownSQL[:len(s.PushdownSQL)-1]
		case len(s.Operators) > 0:
			s.Operators = s.Operators[:len(s.Operators)-1]
			s.OperatorsOmitted++
		default:
			return []byte(`{"error":"summary exceeds max_bytes"}`), true
		}
	}
}

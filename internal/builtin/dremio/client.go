package dremio

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/liubing0806/allowops/internal/builtin/credfile"
	"github.com/liubing0806/allowops/internal/builtin/tsv"
)

// Job states of GET /api/v3/job/{id} that end polling. Every other state,
// including ones this code does not know, keeps the poll going until the
// timeout.
const (
	stateCompleted = "COMPLETED"
	stateCanceled  = "CANCELED"
	stateFailed    = "FAILED"
)

// jobIDPattern admits the ids that Dremio generates and nothing that could
// change the path of a later request.
var jobIDPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z_-]{0,127}$`)

// client talks to one Dremio coordinator. It never follows a redirect, uses no
// proxy and trusts only the system root certificates, so the password and the
// session token go to the configured address and nowhere else.
type client struct {
	http *http.Client
	base string
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                  nil,
			MaxResponseHeaderBytes: 64 << 10,
		},
		// The context of each request bounds it; a client timeout would also cut the cleanup requests.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func newClient(base string) *client { return &client{http: newHTTPClient(), base: base} }

func (c *client) close() { c.http.CloseIdleConnections() }

// statusError carries the HTTP status of a refused request and nothing of its body.
type statusError struct {
	stage  string
	status int
}

func (e *statusError) Error() string {
	return fmt.Sprintf("dremio %s failed (status %d)", e.stage, e.status)
}

func invalidResponse(stage string) error {
	return fmt.Errorf("dremio %s failed (invalid response)", stage)
}

// do sends one request and returns the body of a 2xx response of at most limit
// bytes. Errors name the stage and the status. They never carry the request,
// the response or the transport error, which can hold credentials, tokens, SQL
// or server messages.
func (c *client) do(ctx context.Context, stage, method, path, token string, body any, limit int64) ([]byte, error) {
	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("dremio %s request failed", stage)
		}
		payload = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, payload)
	if err != nil {
		return nil, fmt.Errorf("dremio %s request failed", stage)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "allowops")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "_dremio"+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, transportError(ctx, stage)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, transportError(ctx, stage)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &statusError{stage, resp.StatusCode}
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("dremio %s response exceeds %d bytes", stage, limit)
	}
	return data, nil
}

func transportError(ctx context.Context, stage string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("dremio %s request failed", stage)
}

// login exchanges the account for a session token (POST /apiv2/login). The
// Dremio open-source edition has no access tokens.
func (c *client) login(ctx context.Context, cred credfile.Credential) (string, error) {
	data, err := c.do(ctx, "login", http.MethodPost, "/apiv2/login", "", map[string]string{"userName": cred.Username, "password": cred.Password}, maxControlBody)
	if err != nil {
		return "", err
	}
	var reply struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(data, &reply) != nil || reply.Token == "" {
		return "", invalidResponse("login")
	}
	return reply.Token, nil
}

// logout ends the session (DELETE /apiv2/login); the token stops working at once.
func (c *client) logout(ctx context.Context, token string) error {
	_, err := c.do(ctx, "logout", http.MethodDelete, "/apiv2/login", token, nil, maxControlBody)
	return err
}

func (c *client) submit(ctx context.Context, token, sql string) (string, error) {
	data, err := c.do(ctx, "submit", http.MethodPost, "/api/v3/sql", token, map[string]string{"sql": sql}, maxControlBody)
	if err != nil {
		return "", err
	}
	var reply struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(data, &reply) != nil || !jobIDPattern.MatchString(reply.ID) {
		return "", invalidResponse("submit")
	}
	return reply.ID, nil
}

func (c *client) cancel(ctx context.Context, token, id string) error {
	_, err := c.do(ctx, "cancel", http.MethodPost, "/api/v3/job/"+id+"/cancel", token, map[string]string{"reason": "allowops: the request ended"}, maxControlBody)
	return err
}

// wait polls the job until it reaches a final state or ctx ends. The interval
// doubles up to pollMax.
func (c *client) wait(ctx context.Context, token, id string) (state, message string, err error) {
	delay := pollInitial
	for {
		data, err := c.do(ctx, "status", http.MethodGet, "/api/v3/job/"+id, token, nil, maxControlBody)
		if err != nil {
			return "", "", err
		}
		var job struct {
			JobState     string `json:"jobState"`
			ErrorMessage string `json:"errorMessage"`
		}
		if json.Unmarshal(data, &job) != nil || job.JobState == "" {
			return "", "", invalidResponse("status")
		}
		switch job.JobState {
		case stateCompleted, stateFailed, stateCanceled, "INVALID_STATE":
			return job.JobState, job.ErrorMessage, nil
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", "", ctx.Err()
		case <-timer.C:
		}
		delay = min(delay*2, pollMax)
	}
}

// jobError reports the final state of a job that did not complete. Dremio's
// message can quote the SQL, object names, connection strings and data source
// errors, so only a category chosen from fixed text is returned.
func jobError(state, message string) error {
	if state == stateCanceled {
		return errors.New("dremio job CANCELED")
	}
	return fmt.Errorf("dremio job %s (%s)", state, errorCategory(message))
}

// errorCategory sorts a server message into one of five fixed categories by
// substrings. The classification is a hint for the caller, not a contract.
func errorCategory(message string) string {
	m := strings.ToLower(message)
	has := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(m, w) {
				return true
			}
		}
		return false
	}
	switch {
	case has("access denied", "permission", "unauthorized", "not authorized", "privilege"):
		return "access denied"
	case has("not found"):
		return "object not found"
	case has("memory", "resource", "too many"):
		return "resource limit"
	case has("non-query expression", "encountered", "was expecting", "parse error", "validation error", "single statement", "syntax"):
		return "syntax or validation error"
	}
	return "execution error"
}

// fetch reads the first page of a completed job. Dremio serves at most 500
// rows per request, so max_rows is one page. To see whether the result has
// more rows than max_rows, it asks for one extra row; when max_rows is the
// page size it reads one row past the page instead. The rowCount of the
// response cannot decide this: SHOW, DESCRIBE and EXPLAIN report 0.
func (c *client) fetch(ctx context.Context, token, id string, cfg Config, mask func(string) string) (Result, error) {
	columns, rows, err := c.page(ctx, token, id, 0, min(cfg.MaxRows+1, maxPage))
	if err != nil {
		return Result{}, err
	}
	truncated := len(rows) > cfg.MaxRows
	if truncated {
		rows = rows[:cfg.MaxRows]
	} else if cfg.MaxRows == maxPage && len(rows) == maxPage {
		_, more, err := c.page(ctx, token, id, maxPage, 1)
		if err != nil {
			return Result{}, err
		}
		truncated = len(more) > 0
	}
	return encode(columns, rows, truncated, cfg.MaxBytes, mask)
}

func (c *client) page(ctx context.Context, token, id string, offset, limit int) ([]string, [][]sql.NullString, error) {
	data, err := c.do(ctx, "results", http.MethodGet, fmt.Sprintf("/api/v3/job/%s/results?offset=%d&limit=%d", id, offset, limit), token, nil, maxResultBody)
	if err != nil {
		return nil, nil, err
	}
	columns, rows, err := parsePage(data)
	if err != nil {
		return nil, nil, invalidResponse("results")
	}
	return columns, rows, nil
}

// parsePage reads the schema and the rows. A row is an object keyed by column
// name; a missing key counts as NULL. Cells keep the number text that Dremio
// sent, without a conversion through float64.
func parsePage(data []byte) ([]string, [][]sql.NullString, error) {
	var page struct {
		Schema []struct {
			Name string `json:"name"`
		} `json:"schema"`
		Rows []json.RawMessage `json:"rows"`
	}
	if err := json.Unmarshal(data, &page); err != nil || len(page.Schema) == 0 {
		return nil, nil, errors.New("invalid result")
	}
	columns := make([]string, len(page.Schema))
	for i, column := range page.Schema {
		columns[i] = column.Name
	}
	rows := make([][]sql.NullString, len(page.Rows))
	for i, raw := range page.Rows {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || object == nil {
			return nil, nil, errors.New("invalid row")
		}
		rows[i] = make([]sql.NullString, len(columns))
		for j, name := range columns {
			cell, ok := object[name]
			if !ok {
				continue
			}
			text, err := cellText(cell)
			if err != nil {
				return nil, nil, err
			}
			rows[i][j] = text
		}
	}
	return columns, rows, nil
}

// cellText renders one JSON value as the text of a TSV cell: null is NULL, a
// string is its content, a number or boolean is the text Dremio sent, and an
// object or array is compact JSON.
func cellText(raw json.RawMessage) (sql.NullString, error) {
	raw = bytes.TrimSpace(raw)
	if !json.Valid(raw) {
		return sql.NullString{}, errors.New("invalid cell")
	}
	switch raw[0] {
	case 'n':
		return sql.NullString{}, nil
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return sql.NullString{}, err
		}
		return sql.NullString{String: s, Valid: true}, nil
	case '{', '[':
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			return sql.NullString{}, err
		}
		return sql.NullString{String: compact.String(), Valid: true}, nil
	}
	return sql.NullString{String: string(raw), Valid: true}, nil
}

// encode writes the header and as many rows as fit into maxBytes. The header
// is part of the budget; a header that does not fit is an error, because the
// result would not describe its columns.
func encode(columns []string, rows [][]sql.NullString, truncated bool, maxBytes int64, mask func(string) string) (Result, error) {
	if mask == nil {
		mask = func(s string) string { return s }
	}
	header := make([]string, len(columns))
	for i, column := range columns {
		header[i] = mask(column)
	}
	var out strings.Builder
	tsv.WriteRow(&out, header)
	if int64(out.Len()) > maxBytes {
		return Result{}, errors.New("dremio result header exceeds max_bytes")
	}
	result := Result{Truncated: truncated}
	for _, row := range rows {
		line := strings.Join(tsv.MaskRow(row, mask), "\t") + "\n"
		if int64(out.Len()+len(line)) > maxBytes {
			result.Truncated = true
			break
		}
		out.WriteString(line)
		result.Rows++
	}
	result.Output = out.String()
	return result, nil
}

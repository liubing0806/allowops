package arthas

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Defaults of Config.
const (
	DefaultUsername         = "arthas"
	DefaultMaxResponseBytes = 4 << 20
	DefaultRequestTimeout   = 10 * time.Second
	DefaultExecGrace        = 5 * time.Second
)

// Errors a Client call can wrap; test them with errors.Is.
var (
	// ErrUnauthorized: Arthas answered HTTP 401, the user name or password is wrong.
	ErrUnauthorized = errors.New("arthas: authentication failed (HTTP 401)")
	// ErrResponseTooLarge: the response is longer than Config.MaxResponseBytes.
	ErrResponseTooLarge = errors.New("arthas: response is larger than the limit")
	// ErrInterrupted: the state is INTERRUPTED, the job hit execTimeout and was interrupted.
	ErrInterrupted = errors.New("arthas: job was interrupted")
	// ErrFailed: the state is FAILED.
	ErrFailed = errors.New("arthas: request failed")
	// ErrRefused: the state is REFUSED, for example another job is running in the session.
	ErrRefused = errors.New("arthas: request was refused")
	// ErrCommandNotFound: the command is not registered, which is what a command listed in disabledCommands looks like.
	ErrCommandNotFound = errors.New("arthas: command not found")
	// ErrNoForegroundJob: interrupt_job found no running job in the session.
	ErrNoForegroundJob = errors.New("arthas: no foreground job is running")
	// ErrSessionNotFound: the session ID is unknown or was removed.
	ErrSessionNotFound = errors.New("arthas: session not found")
)

// Config configures a Client.
type Config struct {
	// Dial opens a connection to the Arthas HTTP port. The caller makes it
	// connect from inside the target's network namespace. The Client calls it
	// once per request, possibly from different goroutines, and closes the
	// connection after the response.
	Dial     func(ctx context.Context) (net.Conn, error)
	Username string // DefaultUsername when empty
	Password string
	// MaxResponseBytes limits the HTTP body; DefaultMaxResponseBytes when zero.
	MaxResponseBytes int64
	// RequestTimeout bounds one request other than exec; DefaultRequestTimeout when zero.
	RequestTimeout time.Duration
	// ExecGrace is added to execTimeout for the HTTP request of an exec;
	// DefaultExecGrace when zero.
	ExecGrace time.Duration
}

// Client talks to the Arthas HTTP API of one server.
type Client struct {
	cfg Config
}

// NewClient validates the configuration and applies the defaults.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Dial == nil {
		return nil, errors.New("arthas: Config.Dial is required")
	}
	if cfg.Password == "" {
		return nil, errors.New("arthas: Config.Password is required")
	}
	if cfg.Username == "" {
		cfg.Username = DefaultUsername
	}
	if strings.ContainsRune(cfg.Username, ':') {
		return nil, errors.New("arthas: Config.Username must not contain a colon")
	}
	if cfg.MaxResponseBytes < 0 || cfg.RequestTimeout < 0 || cfg.ExecGrace < 0 {
		return nil, errors.New("arthas: Config limits must not be negative")
	}
	if cfg.MaxResponseBytes == 0 {
		cfg.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = DefaultRequestTimeout
	}
	if cfg.ExecGrace == 0 {
		cfg.ExecGrace = DefaultExecGrace
	}
	return &Client{cfg: cfg}, nil
}

// Result is one element of the results array of an exec response.
type Result struct {
	// Type is the model type: "thread", "jvm", "status", "row_affect", ...
	Type string
	// Raw is the whole JSON object of the result.
	Raw json.RawMessage
}

// UnmarshalJSON keeps the raw object and reads its type.
func (r *Result) UnmarshalJSON(b []byte) error {
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return err
	}
	if head.Type == "" {
		return errors.New("result has no type")
	}
	r.Type = head.Type
	r.Raw = append(json.RawMessage(nil), b...)
	return nil
}

// ExecResponse is the body of a successful exec.
type ExecResponse struct {
	SessionID   string
	JobID       int
	JobStatus   string
	TimeExpired bool
	Results     []Result
}

// Status returns the code and message of the final status result.
// found is false when the response holds no status result.
func (r *ExecResponse) Status() (code int, message string, found bool) {
	for i := len(r.Results) - 1; i >= 0; i-- {
		if r.Results[i].Type != "status" {
			continue
		}
		var st struct {
			StatusCode int    `json:"statusCode"`
			Message    string `json:"message"`
		}
		if err := json.Unmarshal(r.Results[i].Raw, &st); err != nil {
			return 0, "", false
		}
		return st.StatusCode, st.Message, true
	}
	return 0, "", false
}

// StateError is returned when Arthas answers with a state other than SUCCEEDED.
type StateError struct {
	Action  string
	State   string
	Message string
	// Response holds what the server sent with the failure, for example the
	// partial results of an interrupted job. It is nil when the server sent no body.
	Response *ExecResponse
}

func (e *StateError) Error() string {
	msg := "arthas " + e.Action + ": state " + e.State
	if e.State == "" {
		msg = "arthas " + e.Action + ": response has no state"
	}
	if e.Message != "" {
		msg += ": " + e.Message
	}
	return msg
}

// Is maps the state and the message to the sentinel errors.
func (e *StateError) Is(target error) bool {
	switch target {
	case ErrInterrupted:
		return e.State == "INTERRUPTED"
	case ErrFailed:
		return e.State == "FAILED"
	case ErrRefused:
		return e.State == "REFUSED"
	case ErrCommandNotFound:
		return e.State == "FAILED" && strings.Contains(e.Message, "command not found")
	case ErrNoForegroundJob:
		return e.State == "FAILED" && strings.Contains(e.Message, "no foreground job is running")
	case ErrSessionNotFound:
		return e.State == "FAILED" && strings.HasPrefix(e.Message, "session not found")
	}
	return false
}

// RequestError is a failure of the HTTP exchange itself.
type RequestError struct {
	Action string
	// Written is true when the whole request was written to the connection.
	Written bool
	Err     error
}

func (e *RequestError) Error() string { return "arthas " + e.Action + ": " + e.Err.Error() }
func (e *RequestError) Unwrap() error { return e.Err }

type apiRequest struct {
	Action      string `json:"action"`
	Command     string `json:"command,omitempty"`
	SessionID   string `json:"sessionId,omitempty"`
	ConsumerID  string `json:"consumerId,omitempty"`
	ExecTimeout int    `json:"execTimeout,omitempty"`
}

type apiResponse struct {
	State      string          `json:"state"`
	Message    string          `json:"message"`
	SessionID  string          `json:"sessionId"`
	ConsumerID string          `json:"consumerId"`
	Body       json.RawMessage `json:"body"`
}

type execBody struct {
	JobID       int      `json:"jobId"`
	JobStatus   string   `json:"jobStatus"`
	TimeExpired bool     `json:"timeExpired"`
	Results     []Result `json:"results"`
}

// roundTrip sends one request on a new connection and returns the decoded
// response. It does not look at the state.
func (c *Client) roundTrip(ctx context.Context, timeout time.Duration, req apiRequest) (*apiResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	fail := func(written bool, err error) error {
		// The connection deadline equals the context deadline and can fire first.
		if cerr := ctx.Err(); cerr != nil {
			err = fmt.Errorf("%w (%v)", cerr, err)
		} else if errors.Is(err, os.ErrDeadlineExceeded) {
			err = fmt.Errorf("%w (%v)", context.DeadlineExceeded, err)
		}
		return &RequestError{Action: req.Action, Written: written, Err: err}
	}

	conn, err := c.cfg.Dial(ctx)
	if err != nil {
		return nil, fail(false, err)
	}
	defer conn.Close()
	// Closing the connection is the only way to interrupt a blocked Read or
	// Write when the context ends before the deadline of the connection.
	defer context.AfterFunc(ctx, func() { conn.Close() })()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://127.0.0.1/api", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.SetBasicAuth(c.cfg.Username, c.cfg.Password)
	httpReq.Close = true
	if err := httpReq.Write(conn); err != nil {
		return nil, fail(false, err)
	}
	limit := c.cfg.MaxResponseBytes
	// The server is inside the target and may send anything. http.ReadResponse reads a status
	// line and header lines of any length, so the connection itself is bounded too.
	bounded := &boundedReader{
		r:    conn,
		left: limit + maxResponseHead,
		err:  fmt.Errorf("%w (limit %d bytes)", ErrResponseTooLarge, limit+maxResponseHead),
	}
	resp, err := http.ReadResponse(bufio.NewReader(bounded), httpReq)
	if err != nil {
		return nil, fail(true, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("arthas %s: %w", req.Action, ErrUnauthorized)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("arthas %s: unexpected HTTP status %s", req.Action, resp.Status)
	}
	tooLarge := fmt.Errorf("arthas %s: %w (limit %d bytes)", req.Action, ErrResponseTooLarge, limit)
	if resp.ContentLength > limit {
		return nil, tooLarge
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fail(true, err)
	}
	if int64(len(data)) > limit {
		return nil, tooLarge
	}
	var out apiResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("arthas %s: decode response: %w", req.Action, err)
	}
	return &out, nil
}

// maxResponseHead is what a response may have beyond its body: the status line, the headers and
// the framing of a chunked body. Arthas sends a few hundred bytes.
const maxResponseHead = 64 << 10

// boundedReader reads at most left bytes and then fails with err.
type boundedReader struct {
	r    io.Reader
	left int64
	err  error
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, b.err
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.r.Read(p)
	b.left -= int64(n)
	return n, err
}

// call sends a request and turns every state except SUCCEEDED into a StateError.
func (c *Client) call(ctx context.Context, timeout time.Duration, req apiRequest) (*apiResponse, error) {
	resp, err := c.roundTrip(ctx, timeout, req)
	if err != nil {
		return nil, err
	}
	if resp.State == "SUCCEEDED" {
		return resp, nil
	}
	se := &StateError{Action: req.Action, State: resp.State, Message: resp.Message}
	if req.Action == "exec" && len(resp.Body) > 0 {
		if body, err := decodeExec(resp); err == nil {
			se.Response = body
		}
	}
	return nil, se
}

func decodeExec(resp *apiResponse) (*ExecResponse, error) {
	var eb execBody
	if len(resp.Body) > 0 {
		if err := json.Unmarshal(resp.Body, &eb); err != nil {
			return nil, fmt.Errorf("arthas exec: decode body: %w", err)
		}
	}
	return &ExecResponse{
		SessionID:   resp.SessionID,
		JobID:       eb.JobID,
		JobStatus:   eb.JobStatus,
		TimeExpired: eb.TimeExpired,
		Results:     eb.Results,
	}, nil
}

// InitSession creates a session and returns its ID.
func (c *Client) InitSession(ctx context.Context) (string, error) {
	resp, err := c.call(ctx, c.cfg.RequestTimeout, apiRequest{Action: "init_session"})
	if err != nil {
		return "", err
	}
	if resp.SessionID == "" {
		return "", errors.New("arthas init_session: response has no session ID")
	}
	return resp.SessionID, nil
}

// Exec runs a command built by Build in the session and waits for the job to
// end or for cmd.ExecTimeout. An empty sessionID runs the command in a
// one-time session. Only commands returned by Build are accepted.
//
// A state other than SUCCEEDED is returned as a *StateError. A command that
// ran but failed (no such thread, unknown property) is a SUCCEEDED response
// whose Status code is not zero; Render turns it into an error.
func (c *Client) Exec(ctx context.Context, sessionID string, cmd Command) (*ExecResponse, error) {
	if !cmd.built || cmd.Text == "" {
		return nil, errors.New("arthas: Exec accepts only commands returned by Build")
	}
	return c.exec(ctx, sessionID, cmd.Text, cmd.ExecTimeout)
}

// exec sends any command text. Callers inside the package pass fixed words
// (reset, stop) or Command.Text.
func (c *Client) exec(ctx context.Context, sessionID, text string, timeout time.Duration) (*ExecResponse, error) {
	if timeout <= 0 || timeout > MaxExecTimeout {
		return nil, fmt.Errorf("arthas: exec timeout %s is out of range (0, %s]", timeout, MaxExecTimeout)
	}
	// Arthas reads a zero or negative execTimeout as its 30 second default.
	ms := int((timeout + time.Millisecond - 1) / time.Millisecond)
	resp, err := c.call(ctx, timeout+c.cfg.ExecGrace, apiRequest{Action: "exec", Command: text, SessionID: sessionID, ExecTimeout: ms})
	if err != nil {
		return nil, err
	}
	return decodeExec(resp)
}

// InterruptJob interrupts the foreground job of the session. It returns an
// error that matches ErrNoForegroundJob when no job is running.
func (c *Client) InterruptJob(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return errors.New("arthas: interrupt_job needs a session ID")
	}
	_, err := c.call(ctx, c.cfg.RequestTimeout, apiRequest{Action: "interrupt_job", SessionID: sessionID})
	return err
}

// CloseSession removes the session.
func (c *Client) CloseSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return errors.New("arthas: close_session needs a session ID")
	}
	_, err := c.call(ctx, c.cfg.RequestTimeout, apiRequest{Action: "close_session", SessionID: sessionID})
	return err
}

// Session is an Arthas session together with the consumer that receives the results of its
// asynchronous jobs.
type Session struct {
	ID         string
	ConsumerID string
}

// OpenSession creates a session like InitSession and also returns the ID of its result consumer,
// which PullResults needs.
func (c *Client) OpenSession(ctx context.Context) (Session, error) {
	resp, err := c.call(ctx, c.cfg.RequestTimeout, apiRequest{Action: "init_session"})
	if err != nil {
		return Session{}, err
	}
	if resp.SessionID == "" || resp.ConsumerID == "" {
		return Session{}, errors.New("arthas init_session: response has no session or consumer ID")
	}
	return Session{ID: resp.SessionID, ConsumerID: resp.ConsumerID}, nil
}

// AsyncExec starts a command built by Build in the session and returns the ID of its job without
// waiting for it. The results arrive through PullResults; the last one of the job is a status
// result.
//
// Arthas does not apply execTimeout to an asynchronous job: the job ends by itself, when it is
// interrupted or when its session is closed. Build gives every command that runs as a job a limit
// of its own (--timeout, -n).
func (c *Client) AsyncExec(ctx context.Context, s Session, cmd Command) (int, error) {
	if !cmd.built || cmd.Text == "" {
		return 0, errors.New("arthas: AsyncExec accepts only commands returned by Build")
	}
	if s.ID == "" {
		return 0, errors.New("arthas: async_exec needs a session ID")
	}
	req := apiRequest{Action: "async_exec", Command: cmd.Text, SessionID: s.ID}
	resp, err := c.roundTrip(ctx, c.cfg.RequestTimeout, req)
	if err != nil {
		return 0, err
	}
	if resp.State != "SCHEDULED" {
		return 0, &StateError{Action: req.Action, State: resp.State, Message: resp.Message}
	}
	var body struct {
		JobID int `json:"jobId"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil || body.JobID <= 0 {
		return 0, errors.New("arthas async_exec: response has no job ID")
	}
	return body.JobID, nil
}

// PullResults returns the results that arrived for the consumer of the session since the last
// call. Arthas holds the request for up to two seconds while no result arrives, and returns at
// most 20 results at a time.
func (c *Client) PullResults(ctx context.Context, s Session) ([]Result, error) {
	if s.ID == "" || s.ConsumerID == "" {
		return nil, errors.New("arthas: pull_results needs a session and a consumer ID")
	}
	resp, err := c.call(ctx, c.cfg.RequestTimeout, apiRequest{Action: "pull_results", SessionID: s.ID, ConsumerID: s.ConsumerID})
	if err != nil {
		return nil, err
	}
	var body struct {
		Results []Result `json:"results"`
	}
	if len(resp.Body) > 0 {
		if err := json.Unmarshal(resp.Body, &body); err != nil {
			return nil, fmt.Errorf("arthas pull_results: decode body: %w", err)
		}
	}
	return body.Results, nil
}

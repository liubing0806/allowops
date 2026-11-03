package arthas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	// busyAttempts is the number of times RunJob starts a command whose enhancement was refused
	// as busy, and busyPause the wait before it starts it again.
	busyAttempts = 3
	busyPause    = 200 * time.Millisecond
	// maxJobResults bounds the results Follow keeps; a job of a built command produces at most
	// MaxCount of them.
	maxJobResults = 50
	// pullPause is the wait after a pull that returned nothing. Arthas holds a pull for up to two
	// seconds, so the pause only matters for a server that answers at once.
	pullPause = 100 * time.Millisecond
)

// Affect is the enhancer result of an enhancing command: what Arthas changed, reported right
// after the enhancement.
type Affect struct {
	Success bool
	Classes int
	Methods int
	// Message is the reason Arthas gives for a failed enhancement, such as the message that too
	// many classes matched.
	Message string
}

func (a Affect) String() string { return fmt.Sprintf("classes %d, methods %d", a.Classes, a.Methods) }

// enhancerBusy is the message of an enhancement that Arthas refused because the lock of the
// session was taken.
const enhancerBusy = "someone else is enhancing classes, pls. wait."

// Busy reports whether Arthas refused the enhancement because the lock of the session was taken.
// Arthas checks the lock before it touches a class, so nothing was enhanced.
func (a Affect) Busy() bool {
	return !a.Success && a.Classes == 0 && a.Methods == 0 && a.Message == enhancerBusy
}

// AffectError says why an enhancement is outside the limits of its command.
type AffectError struct {
	Affect Affect
	Reason string
}

func (e *AffectError) Error() string { return e.Reason }

// CheckAffect compares an enhancer result with the limits of the command: a successful
// enhancement of one class and of at most MaxMethods methods. -m 1 makes Arthas refuse a second
// class already; the check does not rely on it.
func (c Command) CheckAffect(a Affect) error {
	var reason string
	switch {
	case !a.Success && a.Message != "":
		reason = "the enhancement failed: " + a.Message
	case !a.Success:
		reason = "the enhancement failed"
	case a.Classes != 1:
		reason = fmt.Sprintf("the enhancement affected %d classes, the limit is 1", a.Classes)
	case a.Methods < 1:
		reason = "the enhancement affected no method"
	case a.Methods > c.MaxMethods:
		reason = fmt.Sprintf("the enhancement affected %d methods, the limit is %d", a.Methods, c.MaxMethods)
	default:
		return nil
	}
	return &AffectError{Affect: a, Reason: reason}
}

func parseAffect(raw json.RawMessage) (Affect, error) {
	var m struct {
		Success *bool  `json:"success"`
		Message string `json:"message"`
		Effect  *struct {
			ClassCount   int    `json:"classCount"`
			MethodCount  int    `json:"methodCount"`
			OverLimitMsg string `json:"overLimitMsg"`
		} `json:"effect"`
	}
	if err := json.Unmarshal(raw, &m); err != nil || m.Success == nil || *m.Success && m.Effect == nil {
		return Affect{}, errors.New("arthas: enhancer result without success or effect")
	}
	a := Affect{Success: *m.Success, Message: m.Message}
	if m.Effect != nil {
		a.Classes, a.Methods = m.Effect.ClassCount, m.Effect.MethodCount
		if m.Effect.OverLimitMsg != "" {
			a.Message = m.Effect.OverLimitMsg
		}
	}
	a.Message = strings.TrimSpace(stripANSI(a.Message))
	return a, nil
}

// stripANSI removes the colour sequences Arthas puts into some messages.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] >= '0' && s[j] <= '9' || s[j] == ';') {
				j++
			}
			if j < len(s) && s[j] == 'm' {
				i = j
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Job is what Follow collected of a background job.
type Job struct {
	ID int
	// Affect is the enhancer result, nil until it arrived.
	Affect *Affect
	// Results are the results of the job in their order, without its command, enhancer,
	// input_status and status results.
	Results []Result
	// Dropped counts the results after the first maxJobResults.
	Dropped int
	// Ended is true when the status result of the job arrived, with Code and Message.
	Ended   bool
	Code    int
	Message string
}

// Response returns the results of the job, and its status when it ended, as an exec response
// for Render.
func (j *Job) Response() *ExecResponse {
	results := slices.Clone(j.Results)
	if j.Ended {
		raw, _ := json.Marshal(map[string]any{"type": "status", "jobId": j.ID, "statusCode": j.Code, "message": j.Message})
		results = append(results, Result{Type: "status", Raw: raw})
	}
	return &ExecResponse{JobID: j.ID, Results: results}
}

// Follow reads the results of job id of the session until the status result of the job arrives
// or ctx ends. check is called with the enhancer result as soon as it arrives; when check returns
// an error, Follow returns that error at once and the job keeps running: the caller ends it
// (interrupt_job, then reset). Results of other jobs are skipped.
func (c *Client) Follow(ctx context.Context, s Session, id int, check func(Affect) error) (*Job, error) {
	job := &Job{ID: id}
	for {
		results, err := c.PullResults(ctx, s)
		if err != nil {
			return job, err
		}
		for _, r := range results {
			if resultJob(r) != id {
				continue
			}
			switch r.Type {
			case "enhancer":
				a, err := parseAffect(r.Raw)
				if err != nil {
					return job, err
				}
				job.Affect = &a
				if check != nil {
					if err := check(a); err != nil {
						return job, err
					}
				}
			case "status":
				var st struct {
					StatusCode int    `json:"statusCode"`
					Message    string `json:"message"`
				}
				if err := json.Unmarshal(r.Raw, &st); err != nil {
					return job, fmt.Errorf("arthas: status result: %w", err)
				}
				job.Ended, job.Code, job.Message = true, st.StatusCode, stripANSI(st.Message)
				return job, nil
			case "command", "input_status":
			default:
				if len(job.Results) < maxJobResults {
					job.Results = append(job.Results, r)
				} else {
					job.Dropped++
				}
			}
		}
		if len(results) == 0 {
			t := time.NewTimer(pullPause)
			select {
			case <-ctx.Done():
			case <-t.C:
			}
			t.Stop()
		}
		if err := ctx.Err(); err != nil {
			return job, err
		}
	}
}

// RunJob starts an enhancing command with AsyncExec and follows its job with cmd.CheckAffect as
// the check (see Follow).
//
// The HTTP handler of Arthas holds the lock of the session while it schedules a job, and the
// enhancement of the job takes the same lock. When the job gets there first, Arthas refuses the
// enhancement as busy before it changes a class and ends the job (EnhancerCommand.enhance,
// HttpApiHandler.processAsyncExecRequest). RunJob then waits for the end of that job and starts
// the command again, up to busyAttempts times in all.
func (c *Client) RunJob(ctx context.Context, s Session, cmd Command) (*Job, error) {
	if cmd.Enhance <= 0 {
		return nil, errors.New("arthas: RunJob accepts only enhancing commands")
	}
	for attempt := 1; ; attempt++ {
		id, err := c.AsyncExec(ctx, s, cmd)
		if err != nil {
			return nil, err
		}
		busy := false
		job, err := c.Follow(ctx, s, id, func(a Affect) error {
			if a.Busy() && attempt < busyAttempts {
				busy = true
				return nil
			}
			return cmd.CheckAffect(a)
		})
		if err != nil || !busy || !job.Ended {
			return job, err
		}
		t := time.NewTimer(busyPause)
		select {
		case <-ctx.Done():
			t.Stop()
			return job, ctx.Err()
		case <-t.C:
		}
	}
}

// resultJob returns the job ID of a result, and 0 when it has none.
func resultJob(r Result) int {
	var m struct {
		JobID int `json:"jobId"`
	}
	if json.Unmarshal(r.Raw, &m) != nil {
		return 0
	}
	return m.JobID
}

// Setup sends the setup commands of cmd in the session, in order, and checks that each option
// has the value it was set to.
func (c *Client) Setup(ctx context.Context, sessionID string, cmd Command) error {
	if !cmd.built {
		return errors.New("arthas: Setup accepts only commands returned by Build")
	}
	for _, text := range cmd.Setup {
		resp, err := c.exec(ctx, sessionID, text, cmd.ExecTimeout)
		if err != nil {
			return fmt.Errorf("%s: %w", text, err)
		}
		if code, msg, found := resp.Status(); found && code != 0 {
			return fmt.Errorf("%s: status %d: %s", text, code, msg)
		}
		if err := checkOption(text, resp); err != nil {
			return err
		}
	}
	return nil
}

// checkOption checks the options result of "options <name> <value>".
func checkOption(text string, resp *ExecResponse) error {
	words := strings.Fields(text)
	if len(words) != 3 || words[0] != "options" {
		return fmt.Errorf("arthas: setup command %q is not options <name> <value>", text)
	}
	for _, r := range resp.Results {
		if r.Type != "options" {
			continue
		}
		var m struct {
			ChangeResult *struct {
				Name       string          `json:"name"`
				AfterValue json.RawMessage `json:"afterValue"`
			} `json:"changeResult"`
		}
		if json.Unmarshal(r.Raw, &m) != nil || m.ChangeResult == nil {
			continue
		}
		if m.ChangeResult.Name == words[1] && strings.Trim(string(m.ChangeResult.AfterValue), `"`) == words[2] {
			return nil
		}
		return fmt.Errorf("%s: Arthas reports %s = %s", text, m.ChangeResult.Name, clip(string(m.ChangeResult.AfterValue)))
	}
	return fmt.Errorf("%s: no options result in the response", text)
}

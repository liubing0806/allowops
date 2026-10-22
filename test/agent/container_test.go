//go:build agentcontainer

package agenttest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/agent"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/execd"
	"github.com/liubing0806/allowops/internal/executor"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "invoke-sudo-runner" {
		var request execd.Request
		if json.NewDecoder(os.Stdin).Decode(&request) != nil {
			os.Exit(10)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		a := catalog.Action{Name: request.Action, RunAs: "root", Timeout: "10s", MaxOutput: 1024}
		_, err := (agent.LocalRunner{}).Run(ctx, a, request.Params, nil, request.CatalogID, request.CatalogVersion, executor.Callbacks{})
		if !errors.Is(err, context.DeadlineExceeded) {
			os.Exit(11)
		}
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == "invoke-runner" {
		var input struct {
			Request execd.Request
			Action  catalog.Action
		}
		if json.NewDecoder(os.Stdin).Decode(&input) != nil {
			os.Exit(10)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		encoder := json.NewEncoder(os.Stdout)
		callbacks := executor.Callbacks{
			Started: func() error { return encoder.Encode(execd.Event{Type: "started"}) },
			StepCompleted: func(step executor.StepResult, err error) error {
				return encoder.Encode(execd.Event{Type: "step_completed", Response: &execd.Response{Result: executor.Result{Steps: []executor.StepResult{step}}, Reason: execd.ExecutionReason(err)}})
			},
		}
		r, err := (agent.LocalRunner{}).Run(ctx, input.Action, input.Request.Params, input.Request.Filters, input.Request.CatalogID, input.Request.CatalogVersion, callbacks)
		response := execd.Response{Result: r}
		if err != nil {
			response.Reason = err.Error()
		}
		if encoder.Encode(execd.Event{Type: "completed", Response: &response}) != nil {
			os.Exit(12)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func requireContainer(t *testing.T) {
	t.Helper()
	if os.Getenv("ALLOWOPS_CONTAINER_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires the dedicated root-test container")
	}
}

func signedRequest(t *testing.T, runAs string, spawnPath string) execd.Request {
	t.Helper()
	args := []any{"/usr/local/bin/allowops-test-fixture"}
	if spawnPath != "" {
		args = append(args, "spawn", spawnPath)
	}
	return signedActionRequest(t, catalog.Action{Name: "fixture", Description: "root fixture", Risk: "read", RunAs: runAs, Exec: args, Timeout: "10s", MaxOutput: 4096})
}

func signedActionRequest(t *testing.T, a catalog.Action) execd.Request {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyData, err := catalog.MarshalPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(execd.KeyDirectory, catalog.KeyID(public)+".pem"), keyData, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := catalog.Build(&catalog.Catalog{Config: catalog.Config{SchemaVersion: 1, CatalogID: t.Name()}, Actions: map[string]catalog.Action{a.Name: a}}, catalog.BuildOptions{Now: time.Now(), TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	data, err := catalog.CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := catalog.Sign(data, catalog.SigningKey{PrivateKey: key})
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	path := execd.CatalogPath(execd.CatalogDirectory, p.CatalogID, p.Version)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return execd.Request{CatalogID: p.CatalogID, CatalogVersion: p.Version, Action: a.Name, Params: map[string]any{}}
}

func TestContainerBuiltinHelperFinalReason(t *testing.T) {
	requireContainer(t)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer s.Close()
	for _, scenario := range []string{"TIMEOUT", "FAILED", "CANCELLED"} {
		t.Run(scenario, func(t *testing.T) {
			a := catalog.Action{Name: "http_timeout", Description: "inner timeout", Risk: "read", RunAs: "root", Builtin: "http_get", BuiltinConfig: map[string]any{"allowed_prefixes": []string{s.URL}, "timeout": "100ms"}, Timeout: "5s", MaxOutput: 1024}
			if scenario == "FAILED" {
				a.Builtin = ""
				a.BuiltinConfig = nil
				a.Exec = []any{"/usr/bin/false"}
			}
			request := signedActionRequest(t, a)
			if a.Builtin != "" {
				request.Params = map[string]any{"url": s.URL}
			}
			envelope, err := os.ReadFile(execd.CatalogPath(execd.CatalogDirectory, request.CatalogID, request.CatalogVersion))
			if err != nil {
				t.Fatal(err)
			}
			e, err := catalog.ParseEnvelope(envelope)
			if err != nil {
				t.Fatal(err)
			}
			key, err := os.ReadFile(filepath.Join(execd.KeyDirectory, e.Signatures[0].KeyID+".pem"))
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(struct {
				Action        catalog.Action
				Request       execd.Request
				Envelope, Key []byte
				Expect        string
			}{a, request, envelope, key, scenario})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "/usr/bin/sudo", "-u", "allowops", "/usr/bin/env", "ALLOWOPS_REASON_CONTAINER_CHILD=1", "/tests/agent-tests", "-test.run=^TestRealHelperFinalReason$", "-test.v", "-test.timeout=10s")
			command.Stdin = bytes.NewReader(data)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("real helper reason test: %v\n%s", err, output)
			}
			t.Log(string(output))
		})
	}
}

func TestContainerIdentityAndEnvironment(t *testing.T) {
	requireContainer(t)
	request := signedRequest(t, "nobody", "")
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/libexec/allowops/allowops-exec")
	command.Env = []string{"LD_PRELOAD=/tmp/injected.so", "LD_LIBRARY_PATH=/tmp/injected", "PATH=/tmp/injected", "LANG=injected", "PAGER=injected", "HOME=/tmp/injected", "TMPDIR=/tmp/injected", "ALLOWOPS_CATALOG_DIR=/tmp/injected"}
	command.Stdin = bytes.NewReader(data)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("execute: %v %s", err, output)
	}
	var response execd.Response
	if err := decodeHelperResponse(output, &response); err != nil {
		t.Fatal(err)
	}
	var actual struct {
		UID         int               `json:"uid"`
		GID         int               `json:"gid"`
		Groups      []int             `json:"groups"`
		Environment map[string]string `json:"environment"`
	}
	if err := json.Unmarshal([]byte(response.Result.Stdout), &actual); err != nil {
		t.Fatal(err)
	}
	if actual.UID != 65534 || actual.GID != 65534 {
		t.Fatalf("identity uid=%d gid=%d", actual.UID, actual.GID)
	}
	for _, group := range actual.Groups {
		if group == 0 {
			t.Fatal("root supplementary group retained")
		}
	}
	for name, value := range actual.Environment {
		expected := ""
		if name == "PATH" {
			expected = "/usr/sbin:/usr/bin:/sbin:/bin"
		}
		if name == "LANG" {
			expected = "C.UTF-8"
		}
		if name == "PAGER" {
			expected = "cat"
		}
		if value != expected {
			t.Fatalf("environment %s=%q expected=%q", name, value, expected)
		}
	}
}

func TestContainerSudoCancellationKillsRootProcessGroup(t *testing.T) {
	requireContainer(t)
	path := filepath.Join(t.TempDir(), "pids")
	request := signedRequest(t, "root", path)
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the production LocalRunner as allowops, including sudo's signal
	// forwarding to the root helper and the helper's executor process group.
	command := exec.Command("/usr/bin/sudo", "-u", "allowops", "/tests/root-tests", "invoke-sudo-runner")
	command.Stdin = bytes.NewReader(data)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("sudo cancellation: %v %s", err, output)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int
	if err := json.Unmarshal(data, &ids); err != nil || len(ids) != 2 {
		t.Fatalf("pids: %v %v", ids, err)
	}
	defer syscall.Kill(-ids[0], syscall.SIGKILL)
	for _, id := range ids {
		deadline := time.Now().Add(3 * time.Second)
		for {
			data, err := os.ReadFile("/proc/" + strconv.Itoa(id) + "/stat")
			if os.IsNotExist(err) {
				break
			}
			text := string(data)
			index := strings.LastIndex(text, ") ")
			if index >= 0 && len(text) > index+2 && text[index+2] == 'Z' {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("root process %d still alive: %s", id, data)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestContainerAttacks(t *testing.T) {
	requireContainer(t)
	for _, mode := range []string{"tamper", "catalog-symlink", "state-symlink", "state-owner", "unknown-user", "stdin-limit"} {
		t.Run(mode, func(t *testing.T) {
			runAs := "root"
			if mode == "unknown-user" {
				runAs = "allowops_nonexistent_198765"
			}
			request := signedRequest(t, runAs, "")
			path := execd.CatalogPath(execd.CatalogDirectory, request.CatalogID, request.CatalogVersion)
			switch mode {
			case "tamper":
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, bytes.Replace(data, []byte("payloadType"), []byte("payloadTypX"), 1), 0600); err != nil {
					t.Fatal(err)
				}
			case "catalog-symlink":
				outside := filepath.Join(t.TempDir(), "package")
				if err := os.Rename(path, outside); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			case "state-symlink":
				if err := os.Rename(execd.StateDirectory, execd.StateDirectory+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), execd.StateDirectory); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_ = os.Remove(execd.StateDirectory)
					if err := os.Rename(execd.StateDirectory+".original", execd.StateDirectory); err != nil {
						t.Error(err)
					}
				})
			case "state-owner":
				if err := os.Chown(execd.StateDirectory, 65534, 65534); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Chown(execd.StateDirectory, 0, 0); err != nil {
						t.Error(err)
					}
				})
			}
			data, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "stdin-limit" {
				data = bytes.Repeat([]byte("x"), execd.MaxRequestBytes+1)
			}
			command := exec.Command("/usr/libexec/allowops/allowops-exec")
			command.Stdin = bytes.NewReader(data)
			output, err := command.Output()
			if err == nil {
				t.Fatalf("attack %s accepted: %s", mode, output)
			}
			var response execd.Response
			if err := decodeHelperResponse(output, &response); err != nil || response.Reason == "" {
				t.Fatalf("missing refusal: %s %v", output, err)
			}
		})
	}
}

func decodeHelperResponse(data []byte, response *execd.Response) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	completed := false
	for {
		var event execd.Event
		if err := decoder.Decode(&event); err != nil {
			if err == io.EOF && completed {
				return nil
			}
			return errors.New("missing final helper event")
		}
		if completed {
			return errors.New("event after completion")
		}
		if event.Type == "completed" && event.Response != nil {
			*response = *event.Response
			completed = true
		}
	}
}

func invokeRunner(t *testing.T, request execd.Request, action catalog.Action) ([]execd.Event, execd.Response) {
	t.Helper()
	data, err := json.Marshal(struct {
		Request execd.Request
		Action  catalog.Action
	}{request, action})
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/bin/sudo", "-u", "allowops", "/tests/root-tests", "invoke-runner")
	command.Stdin = bytes.NewReader(data)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("runner: %v %s", err, output)
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	var events []execd.Event
	for {
		var event execd.Event
		if err := decoder.Decode(&event); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if len(events) == 0 || events[len(events)-1].Type != "completed" || events[len(events)-1].Response == nil {
		t.Fatalf("events=%+v", events)
	}
	return events, *events[len(events)-1].Response
}

func TestContainerImplicitRootRedisRefusal(t *testing.T) {
	requireContainer(t)
	a := catalog.Action{Name: "redis_read", Description: "root credential", Risk: "read", Builtin: "redis_command", BuiltinConfig: map[string]any{"address": "unix:///tmp/no-redis.sock", "credential": "/etc/allowops/missing-redis.json"}, Timeout: "5s", MaxOutput: 1024}
	request := signedActionRequest(t, a)
	request.Params = map[string]any{"command": "GET", "args": []string{"key"}}
	events, response := invokeRunner(t, request, a)
	if len(events) != 2 || events[0].Type != "started" || response.Reason != "EXECUTION_FAILED" || response.Result.ExitCode != 1 {
		t.Fatalf("events=%+v response=%+v", events, response)
	}
	state, err := os.ReadFile(filepath.Join(execd.StateDirectory, execd.CatalogHash(request.CatalogID)+".version"))
	if err != nil || strings.TrimSpace(string(state)) != strconv.FormatInt(request.CatalogVersion, 10) {
		t.Fatalf("root helper did not verify catalog: state=%q err=%v", state, err)
	}
}

func TestContainerSudoStepsEventsAndFilters(t *testing.T) {
	requireContainer(t)
	a := catalog.Action{Name: "root_steps", Description: "steps through sudo", Risk: "read", RunAs: "root", Steps: []catalog.Step{{Name: "first", Exec: []any{"/usr/bin/printf", "password=secret\\nvisible\\n"}}, {Name: "fail", Exec: []any{"/usr/bin/false"}}, {Name: "skip", Exec: []any{"/usr/bin/printf", "skip"}}}, OnError: "stop", Filters: []string{"match"}, Timeout: "5s", MaxOutput: 1024}
	request := signedActionRequest(t, a)
	request.Filters = map[string]any{"match": "visible"}
	events, response := invokeRunner(t, request, a)
	if len(events) != 5 || events[0].Type != "started" || response.Reason != "" || response.Result.ExitCode != 1 {
		t.Fatalf("events=%+v response=%+v", events, response)
	}
	for index := 0; index < 3; index++ {
		e := events[index+1]
		if e.Type != "step_completed" || e.Response == nil || len(e.Response.Result.Steps) != 1 || e.Response.Result.Steps[0].Index != index {
			t.Fatalf("step event=%+v", e)
		}
	}
	steps := response.Result.Steps
	if len(steps) != 3 || steps[0].Stdout != "visible\n" || !steps[2].Skipped || steps[2].ExitCode != nil {
		t.Fatalf("steps=%+v", steps)
	}
}

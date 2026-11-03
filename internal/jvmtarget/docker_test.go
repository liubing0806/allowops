package jvmtarget

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordedRequest struct{ method, path, rawQuery string }

// dockerDaemon serves a fake Docker Engine API on a unix socket.
func dockerDaemon(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) (socket string, requests func() []recordedRequest) {
	t.Helper()
	dir, err := os.MkdirTemp("", "dk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket = filepath.Join(dir, "docker.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []recordedRequest
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, recordedRequest{r.Method, r.URL.EscapedPath(), r.URL.RawQuery})
		mu.Unlock()
		handler(w, r)
	})}
	go server.Serve(l)
	t.Cleanup(func() { server.Close() })
	return socket, func() []recordedRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]recordedRequest(nil), seen...)
	}
}

// inspect mimics the container inspect document of the container with the given name; its
// Config.Env holds secrets.
func inspect(name, state string) string {
	return `{"Id":"abc","Name":"/` + name + `","State":` + state + `,"Config":{"Env":["DB_PASSWORD=CANARY-env"],"Cmd":["java","-jar","x.jar"]}}`
}

func TestDockerContainerPID(t *testing.T) {
	socket, requests := dockerDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/web/json":
			w.Write([]byte(inspect("web", `{"Status":"running","Running":true,"Paused":false,"Restarting":false,"Pid":4242,"StartedAt":"2026-10-23T00:00:00Z"}`)))
		case "/containers/paused/json":
			w.Write([]byte(inspect("paused", `{"Status":"paused","Running":true,"Paused":true,"Pid":4243}`)))
		case "/containers/stopped/json":
			w.Write([]byte(inspect("stopped", `{"Status":"exited","Running":false,"Pid":0}`)))
		case "/containers/restarting/json":
			w.Write([]byte(inspect("restarting", `{"Status":"restarting","Running":true,"Restarting":true,"Pid":0}`)))
		case "/containers/nopid/json":
			w.Write([]byte(inspect("nopid", `{"Status":"running","Running":true,"Pid":0}`)))
		case "/containers/negpid/json":
			w.Write([]byte(inspect("negpid", `{"Status":"running","Running":true,"Pid":-5}`)))
		case "/containers/garbage/json":
			w.Write([]byte("<html>CANARY-body</html>"))
		case "/containers/huge/json":
			w.Write([]byte(`{"State":{"Running":true,"Pid":7},"Pad":"` + strings.Repeat("x", 9<<20) + `"}`))
		case "/containers/boom/json":
			http.Error(w, "CANARY-error-body", http.StatusInternalServerError)
		default:
			http.Error(w, `{"message":"No such container: x"}`, http.StatusNotFound)
		}
	})
	ctx := context.Background()
	pid, err := dockerContainerPID(ctx, socket, "web")
	if err != nil || pid != 4242 {
		t.Fatalf("pid = %d, %v", pid, err)
	}
	reqs := requests()
	if len(reqs) != 1 || reqs[0].method != "GET" || reqs[0].path != "/containers/web/json" || reqs[0].rawQuery != "" {
		t.Errorf("requests = %+v; want one GET /containers/web/json", reqs)
	}
	for name, want := range map[string]string{
		"paused":     "paused",
		"stopped":    "not running",
		"restarting": "not running",
		"nopid":      "no main process",
		"negpid":     "invalid",
		"garbage":    "",
		"huge":       "",
		"boom":       "",
		"missing":    "no such container",
	} {
		pid, err := dockerContainerPID(ctx, socket, name)
		if err == nil {
			t.Errorf("%s: pid %d accepted", name, pid)
			continue
		}
		if !strings.Contains(strings.ToLower(err.Error()), want) {
			t.Errorf("%s: err = %v; want it to mention %q", name, err, want)
		}
		if strings.Contains(err.Error(), "CANARY") {
			t.Errorf("%s: error leaks the response body: %v", name, err)
		}
	}
	for _, r := range requests() {
		if r.method != "GET" || !strings.HasPrefix(r.path, "/containers/") || !strings.HasSuffix(r.path, "/json") {
			t.Errorf("unexpected request %+v", r)
		}
	}
}

// A container reference that is a hexadecimal prefix of an ID matches a container by ID when no
// container has that name. The configured name must be the name of the container that answers.
func TestDockerContainerPIDRejectsAnotherContainer(t *testing.T) {
	running := `{"Status":"running","Running":true,"Pid":4242}`
	socket, _ := dockerDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/db/json":
			// No container is named "db"; this one has an ID that starts with it.
			w.Write([]byte(`{"Id":"db3f9a0c","Name":"/billing","State":` + running + `}`))
		case "/containers/ab12/json":
			// A name that also reads as an ID prefix, with a container whose name merely starts with it.
			w.Write([]byte(`{"Id":"ab12ff","Name":"/ab12-old","State":` + running + `}`))
		case "/containers/noname/json":
			w.Write([]byte(`{"Id":"abc","State":` + running + `}`))
		case "/containers/Web/json":
			// Names are case sensitive.
			w.Write([]byte(inspect("web", running)))
		default:
			// The name in the document is the name that was asked for.
			w.Write([]byte(inspect(strings.Split(r.URL.Path, "/")[2], running)))
		}
	})
	for _, name := range []string{"db", "ab12", "noname", "Web"} {
		pid, err := dockerContainerPID(context.Background(), socket, name)
		if err == nil {
			t.Errorf("%s: pid %d accepted", name, pid)
			continue
		}
		if strings.Contains(err.Error(), "billing") || strings.Contains(err.Error(), "ab12-old") {
			t.Errorf("%s: error names another container: %v", name, err)
		}
	}
	for _, name := range []string{"db3f9a0c", "ab12-old", "billing"} {
		if pid, err := dockerContainerPID(context.Background(), socket, name); err != nil || pid != 4242 {
			t.Errorf("%s: pid = %d, %v", name, pid, err)
		}
	}
}

func TestDockerContainerPIDEscapesAndRejectsNames(t *testing.T) {
	socket, requests := dockerDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "{}", http.StatusNotFound)
	})
	for _, name := range []string{"", "a/b", "../etc", "a b", "web?all=1", "web#x", "-x", "a%2Fb", "web\n"} {
		if pid, err := dockerContainerPID(context.Background(), socket, name); err == nil {
			t.Errorf("%q: pid %d", name, pid)
		}
	}
	if reqs := requests(); len(reqs) != 0 {
		t.Errorf("invalid names reached the daemon: %+v", reqs)
	}
}

func TestDockerContainerPIDSocketErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "none.sock")
	_, err := dockerContainerPID(context.Background(), missing, "web")
	if err == nil || !strings.Contains(err.Error(), missing) {
		t.Errorf("err = %v; want it to name the socket", err)
	}
	// A daemon that never answers is bounded by the context.
	socket, _ := dockerDaemon(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(3 * time.Second) })
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := dockerContainerPID(ctx, socket, "web"); err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("err = %v after %v", err, time.Since(start))
	}
}

func fakeSystemctl(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "systemctl")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSystemdMainPID(t *testing.T) {
	args := filepath.Join(t.TempDir(), "args")
	ok := fakeSystemctl(t, `echo "$@" > `+args+`
echo "MainPID=4242"`)
	pid, err := systemdMainPID(context.Background(), ok, "api.service")
	if err != nil || pid != 4242 {
		t.Fatalf("pid = %d, %v", pid, err)
	}
	got, _ := os.ReadFile(args)
	if strings.TrimSpace(string(got)) != "show --property=MainPID -- api.service" {
		t.Errorf("systemctl arguments = %q", got)
	}
	for name, script := range map[string]string{
		"stopped":   `echo "MainPID=0"`,
		"garbage":   `echo "MainPID=abc"`,
		"negative":  `echo "MainPID=-3"`,
		"empty":     `true`,
		"two lines": "echo MainPID=1\necho MainPID=2",
		"failure":   `echo "Failed to connect to bus: CANARY-detail" >&2; exit 1`,
		"other key": `echo "ControlPID=4242"`,
	} {
		pid, err := systemdMainPID(context.Background(), fakeSystemctl(t, script), "api.service")
		if err == nil {
			t.Errorf("%s: pid %d accepted", name, pid)
		}
	}
	if _, err := systemdMainPID(context.Background(), filepath.Join(t.TempDir(), "missing"), "api.service"); err == nil {
		t.Error("a missing systemctl was accepted")
	}
}

func TestSystemdMainPIDStoppedUnitIsNotRunning(t *testing.T) {
	_, err := systemdMainPID(context.Background(), fakeSystemctl(t, `echo "MainPID=0"`), "api.service")
	if !errors.Is(err, ErrNotRunning) {
		t.Errorf("err = %v; want ErrNotRunning", err)
	}
}

// The real systemctl: the journal runs on any systemd host.
func TestSystemdMainPIDWithSystemctl(t *testing.T) {
	const systemctl = "/usr/bin/systemctl"
	if _, err := os.Stat(systemctl); err != nil {
		t.Skip("no systemctl")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Skip("not booted with systemd")
	}
	pid, err := systemdMainPID(context.Background(), systemctl, "systemd-journald.service")
	if err != nil || pid < 1 {
		t.Fatalf("pid = %d, %v", pid, err)
	}
	comm, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil || !strings.Contains(string(comm), "journal") {
		t.Errorf("pid %d is %q, %v", pid, comm, err)
	}
	if _, err := systemdMainPID(context.Background(), systemctl, "allowops-no-such-unit.service"); err == nil {
		t.Error("a unit that does not exist has a main pid")
	}
}

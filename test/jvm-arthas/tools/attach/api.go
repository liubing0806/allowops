package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// sysSetns is the x86-64 number of setns(2); package syscall does not export it. The tool is x86-64 only.
const sysSetns = 308

type apiResult struct {
	Status    int               `json:"status"`
	Headers   map[string]string `json:"headers,omitempty"`
	Body      json.RawMessage   `json:"body,omitempty"`
	RawBody   string            `json:"raw_body,omitempty"`
	ElapsedMs float64           `json:"elapsed_ms"`
	Error     string            `json:"error,omitempty"`
}

// cmdAPI enters the network namespace of the target and sends one HTTP request to Arthas.
// Everything happens on one locked OS thread: the dial must run in the target namespace, and a
// goroutine-per-dial HTTP client would not guarantee that.
func cmdAPI(args []string) (any, error) {
	fs := flag.NewFlagSet("api", flag.ExitOnError)
	pid := fs.Int("pid", 0, "host pid of the target JVM (its network namespace is entered)")
	host := fs.String("host", "127.0.0.1", "address inside the target namespace")
	port := fs.Int("port", 0, "Arthas HTTP port")
	method := fs.String("method", "POST", "HTTP method")
	path := fs.String("path", "/api", "request path")
	user := fs.String("user", "arthas", "Basic auth user")
	passFile := fs.String("pass-file", "", "file with the Basic auth password")
	noAuth := fs.Bool("no-auth", false, "send no Authorization header")
	action := fs.String("action", "", "API action: exec, async_exec, init_session, close_session, interrupt_job, pull_results, session_info, join_session")
	cmd := fs.String("cmd", "", "Arthas command line (exec, async_exec)")
	session := fs.String("session", "", "session id")
	consumer := fs.String("consumer", "", "consumer id (pull_results)")
	execTimeout := fs.Int("exec-timeout", 0, "execTimeout in ms for exec")
	body := fs.String("body", "", "send this body instead of building one from -action")
	timeout := fs.Duration("timeout", 60*time.Second, "whole-request timeout")
	hostNS := fs.Bool("host-ns", false, "do not enter the target namespace (reachability test from the host)")
	_ = fs.Parse(args)
	if *port == 0 || (*pid == 0 && !*hostNS) {
		return nil, errors.New("-port and -pid are required")
	}

	var payload string
	switch {
	case *body != "":
		payload = *body
	case *method == "POST":
		m := map[string]any{"action": *action}
		if *cmd != "" {
			m["command"] = *cmd
		}
		if *session != "" {
			m["sessionId"] = *session
		}
		if *consumer != "" {
			m["consumerId"] = *consumer
		}
		if *execTimeout > 0 {
			m["execTimeout"] = *execTimeout
		}
		b, _ := json.Marshal(m)
		payload = string(b)
	}

	runtime.LockOSThread() // never unlocked: the thread is dropped when the process exits
	if !*hostNS {
		f, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", *pid))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if _, _, e := syscall.RawSyscall(sysSetns, f.Fd(), syscall.CLONE_NEWNET, 0); e != 0 {
			return nil, fmt.Errorf("setns: %w", e)
		}
	}

	start := time.Now()
	res := &apiResult{}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", *host, *port), 5*time.Second)
	if err != nil {
		res.Error = err.Error()
		res.ElapsedMs = ms(time.Since(start))
		return res, nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(*timeout))

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n", *method, *path, *host, *port)
	if !*noAuth && *passFile != "" {
		pw, err := os.ReadFile(*passFile)
		if err != nil {
			return nil, err
		}
		cred := base64.StdEncoding.EncodeToString([]byte(*user + ":" + strings.TrimSpace(string(pw))))
		fmt.Fprintf(&sb, "Authorization: Basic %s\r\n", cred)
	}
	if payload != "" {
		fmt.Fprintf(&sb, "Content-Type: application/json\r\nContent-Length: %d\r\n", len(payload))
	}
	sb.WriteString("\r\n" + payload)
	if _, err := io.WriteString(conn, sb.String()); err != nil {
		res.Error = err.Error()
		return res, nil
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		res.Error = err.Error()
		res.ElapsedMs = ms(time.Since(start))
		return res, nil
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	res.ElapsedMs = ms(time.Since(start))
	res.Status = resp.StatusCode
	res.Headers = map[string]string{}
	for _, h := range []string{"Content-Type", "WWW-Authenticate", "Set-Cookie", "Location"} {
		if v := resp.Header.Get(h); v != "" {
			res.Headers[h] = v
		}
	}
	if err != nil {
		res.Error = err.Error()
	}
	if json.Valid(data) {
		res.Body = data
	} else {
		raw := string(data)
		if len(raw) > 2000 {
			raw = raw[:2000] + "...(truncated)"
		}
		res.RawBody = raw
	}
	return res, nil
}

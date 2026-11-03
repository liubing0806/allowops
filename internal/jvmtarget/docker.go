package jvmtarget

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
)

// maxInspectBytes bounds the container inspect document. It lists the
// container's environment, so it is parsed for one field and never kept or logged.
const maxInspectBytes = 8 << 20

// dockerContainerPID asks the Docker Engine API for the host pid of the
// container's main process. The only request is GET /containers/<name>/json.
func dockerContainerPID(ctx context.Context, socket, name string) (int, error) {
	if !containerPattern.MatchString(name) || len(name) > maxContainerLen {
		return 0, fmt.Errorf("invalid container name %q", name)
	}
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives: true,
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/"+name+"/json", nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("docker API at %s: %w", socket, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return 0, fmt.Errorf("no such container %q", name)
	case resp.StatusCode != http.StatusOK:
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return 0, fmt.Errorf("docker API answered %s for container %q", resp.Status, name)
	}
	var doc struct {
		State struct {
			Pid        int
			Running    bool
			Paused     bool
			Restarting bool
		}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxInspectBytes+1)).Decode(&doc); err != nil {
		return 0, fmt.Errorf("docker API: unreadable inspect document for container %q", name)
	}
	state := doc.State
	switch {
	case state.Paused:
		return 0, fmt.Errorf("container %q is paused: %w", name, ErrNotRunning)
	case !state.Running || state.Restarting:
		return 0, fmt.Errorf("container %q is not running: %w", name, ErrNotRunning)
	case state.Pid == 0:
		return 0, fmt.Errorf("container %q has no main process: %w", name, ErrNotRunning)
	case state.Pid < 0:
		return 0, fmt.Errorf("docker API: invalid pid for container %q", name)
	}
	return state.Pid, nil
}

// systemdMainPID runs systemctl show to read the MainPID of a unit. Without a
// main process MainPID is 0, which means the unit is not running.
func systemdMainPID(ctx context.Context, systemctl, unit string) (int, error) {
	// "--value" needs systemd 230; CentOS 7 has 219, so the key is parsed instead.
	cmd := exec.CommandContext(ctx, systemctl, "show", "--property=MainPID", "--", unit)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	var stdout bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, left: 4096}
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, fmt.Errorf("systemctl show %s failed: %w", unit, err)
	}
	text := strings.TrimSpace(stdout.String())
	value, ok := strings.CutPrefix(text, "MainPID=")
	if !ok || strings.Contains(text, "\n") {
		return 0, fmt.Errorf("unexpected systemctl output for %s", unit)
	}
	pid, err := strconv.Atoi(value)
	if err != nil || pid < 0 {
		return 0, fmt.Errorf("unexpected MainPID for %s", unit)
	}
	if pid == 0 {
		return 0, fmt.Errorf("unit %s has no main process: %w", unit, ErrNotRunning)
	}
	return pid, nil
}

// limitedWriter keeps at most left bytes and drops the rest.
type limitedWriter struct {
	w    io.Writer
	left int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	n := len(p)
	if n > l.left {
		p = p[:l.left]
	}
	l.left -= len(p)
	if _, err := l.w.Write(p); err != nil {
		return 0, err
	}
	return n, nil
}

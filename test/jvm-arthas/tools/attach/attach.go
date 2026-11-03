package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

type loadResult struct {
	OK           bool        `json:"ok"`
	Stage        string      `json:"stage"` // where it stopped: ok, status, socket, connect, request, response
	Error        string      `json:"error,omitempty"`
	Reply        string      `json:"reply,omitempty"` // raw reply of the attach listener: first line is the return code
	ReplyCode    string      `json:"reply_code,omitempty"`
	SocketPath   string      `json:"socket_path,omitempty"`
	SocketReused bool        `json:"socket_reused"` // the listener was already initialised, no SIGQUIT sent
	AttachFileAt string      `json:"attach_file_at,omitempty"`
	FileOwner    string      `json:"file_owner"`
	ConnUser     string      `json:"conn_user"`
	SignalMs     float64     `json:"signal_to_socket_ms"`
	ConnectMs    float64     `json:"connect_ms"`
	LoadMs       float64     `json:"request_to_reply_ms"`
	TotalMs      float64     `json:"total_ms"`
	ArgLen       int         `json:"agent_arg_len"`
	Target       *procStatus `json:"target,omitempty"`
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// cmdLoad performs the HotSpot attach handshake by hand:
//  1. if /tmp/.java_pid<nspid> is missing: create .attach_pid<nspid>, send SIGQUIT, wait for the socket;
//  2. connect to the socket and send  "1\0load\0instrument\0false\0<agent>=<options>\0".
func cmdLoad(args []string) (any, error) {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	pid := fs.Int("pid", 0, "host pid of the target JVM")
	agent := fs.String("agent", "", "arthas-agent.jar path as seen inside the container")
	core := fs.String("core", "", "arthas-core.jar path as seen inside the container")
	opts := fs.String("opts", "", "agent options, key=value;key=value (non-secret only: visible in ps)")
	optsFile := fs.String("opts-file", "", "file holding the agent options (use this for the password)")
	rawArg := fs.String("raw-arg", "", "send this as the whole agent argument instead of <agent>=<core>;<opts> (for the length test)")
	fileOwner := fs.String("file-owner", "root", "owner of .attach_pid: root or target")
	connUser := fs.String("conn-user", "root", "uid used to connect to the socket: root or target")
	fileDir := fs.String("file-dir", "cwd", "where to create .attach_pid: cwd, tmp, both or none")
	wait := fs.Duration("wait", 10*time.Second, "how long to wait for the socket")
	noSignal := fs.Bool("no-signal", false, "never send SIGQUIT (checks whether the socket alone is enough)")
	keepFile := fs.Bool("keep-file", false, "leave .attach_pid in place")
	_ = fs.Parse(args)
	if *pid == 0 {
		return nil, errors.New("-pid is required")
	}

	res := &loadResult{Stage: "status", FileOwner: *fileOwner, ConnUser: *connUser}
	start := time.Now()
	st, err := readStatus(*pid)
	if err != nil {
		return res.fail("status", err), nil
	}
	res.Target = st

	option := *opts
	if *optsFile != "" {
		b, err := os.ReadFile(*optsFile)
		if err != nil {
			return nil, err
		}
		option = strings.TrimSpace(string(b))
	}
	arg := *agent + "=" + *core
	if option != "" {
		arg += ";" + option
	}
	if *rawArg != "" {
		arg = *rawArg
	}
	res.ArgLen = len(arg)

	root := fmt.Sprintf("/proc/%d/root", *pid)
	sock := fmt.Sprintf("%s/tmp/.java_pid%d", root, st.NSpid)
	res.SocketPath = fmt.Sprintf("/tmp/.java_pid%d", st.NSpid)

	cleanup := func() {} // removes .attach_pid; must run while still root, before the uid switch below
	if _, err := os.Stat(sock); err == nil {
		res.SocketReused = true
	} else if !*noSignal {
		name := fmt.Sprintf(".attach_pid%d", st.NSpid)
		var created []string
		for _, dir := range fileDirs(*fileDir, *pid) {
			p := dir + "/" + name
			f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o660)
			if err != nil {
				return res.fail("request", fmt.Errorf("create %s: %w", p, err)), nil
			}
			f.Close()
			if *fileOwner == "target" {
				if err := os.Chown(p, st.UID, st.GID); err != nil {
					return res.fail("request", err), nil
				}
			}
			created = append(created, p)
		}
		res.AttachFileAt = strings.Join(created, ",")
		cleanup = func() {
			if !*keepFile {
				for _, p := range created {
					os.Remove(p)
				}
			}
		}
		defer cleanup()
		sent := time.Now()
		if err := syscall.Kill(*pid, syscall.SIGQUIT); err != nil {
			return res.fail("request", fmt.Errorf("SIGQUIT: %w", err)), nil
		}
		deadline := sent.Add(*wait)
		for {
			if _, err := os.Stat(sock); err == nil {
				break
			}
			if time.Now().After(deadline) {
				res.SignalMs = ms(time.Since(sent))
				return res.fail("socket", errors.New("socket did not appear")), nil
			}
			time.Sleep(5 * time.Millisecond)
		}
		res.SignalMs = ms(time.Since(sent))
	}

	cleanup()
	if *connUser == "target" {
		if err := syscall.Setgid(st.GID); err != nil {
			return res.fail("connect", err), nil
		}
		if err := syscall.Setuid(st.UID); err != nil {
			return res.fail("connect", err), nil
		}
	}

	t0 := time.Now()
	conn, err := net.DialTimeout("unix", sock, 5*time.Second)
	res.ConnectMs = ms(time.Since(t0))
	if err != nil {
		return res.fail("connect", err), nil
	}
	defer conn.Close()

	// version, command, three arguments, each NUL-terminated
	req := "1\x00load\x00instrument\x00false\x00" + arg + "\x00"
	t1 := time.Now()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.WriteString(conn, req); err != nil {
		return res.fail("request", err), nil
	}
	reply, err := io.ReadAll(conn)
	res.LoadMs = ms(time.Since(t1))
	res.Reply = string(reply)
	if first, _, _ := strings.Cut(res.Reply, "\n"); first != "" {
		res.ReplyCode = strings.TrimSpace(first)
	}
	if err != nil {
		return res.fail("response", err), nil
	}
	res.TotalMs = ms(time.Since(start))
	res.OK = res.ReplyCode == "0"
	res.Stage = "ok"
	if !res.OK {
		res.Stage = "response"
	}
	return res, nil
}

func fileDirs(mode string, pid int) []string {
	cwd := fmt.Sprintf("/proc/%d/cwd", pid)
	tmp := fmt.Sprintf("/proc/%d/root/tmp", pid)
	switch mode {
	case "cwd":
		return []string{cwd}
	case "tmp":
		return []string{tmp}
	case "both":
		return []string{cwd, tmp}
	}
	return nil
}

func (r *loadResult) fail(stage string, err error) *loadResult {
	r.Stage = stage
	r.Error = err.Error()
	return r
}

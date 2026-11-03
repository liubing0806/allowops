package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// procStatus holds the fields of /proc/<pid>/status that the attach protocol and the plan's checks use.
type procStatus struct {
	Pid     int    `json:"pid"`
	NSpid   int    `json:"nspid"` // pid inside the innermost pid namespace; names .attach_pid / .java_pid
	UID     int    `json:"uid"`   // effective
	GID     int    `json:"gid"`   // effective
	SigBlk  string `json:"sigblk"`
	SigIgn  string `json:"sigign"`
	SigCgt  string `json:"sigcgt"`
	Quit    bool   `json:"sigquit_caught"`
	QuitIgn bool   `json:"sigquit_ignored"`
	QuitBlk bool   `json:"sigquit_blocked"`
	Cwd     string `json:"cwd"`
	Threads int    `json:"threads"`
}

const sigquitBit = 1 << (3 - 1) // signal 3 is bit 2 of the mask

func readStatus(pid int) (*procStatus, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st := &procStatus{Pid: pid, NSpid: pid}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		fields := strings.Fields(val)
		switch key {
		case "Uid":
			if len(fields) >= 2 {
				st.UID, _ = strconv.Atoi(fields[1])
			}
		case "Gid":
			if len(fields) >= 2 {
				st.GID, _ = strconv.Atoi(fields[1])
			}
		case "NSpid":
			if len(fields) >= 1 {
				st.NSpid, _ = strconv.Atoi(fields[len(fields)-1])
			}
		case "SigBlk":
			st.SigBlk = val
		case "SigIgn":
			st.SigIgn = val
		case "SigCgt":
			st.SigCgt = val
		case "Threads":
			st.Threads, _ = strconv.Atoi(val)
		}
	}
	st.Quit = maskHas(st.SigCgt, sigquitBit)
	st.QuitIgn = maskHas(st.SigIgn, sigquitBit)
	st.QuitBlk = maskHas(st.SigBlk, sigquitBit)
	st.Cwd, _ = os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	return st, sc.Err()
}

func maskHas(hex string, bit uint64) bool {
	v, err := strconv.ParseUint(strings.TrimSpace(hex), 16, 64)
	return err == nil && v&bit != 0
}

func cmdInspect(args []string) (any, error) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	pid := fs.Int("pid", 0, "host pid of the target JVM")
	_ = fs.Parse(args)
	if *pid == 0 {
		return nil, fmt.Errorf("-pid is required")
	}
	return readStatus(*pid)
}

type listener struct {
	Proto string `json:"proto"`
	Addr  string `json:"addr"`
	Port  int    `json:"port"`
	Inode string `json:"inode"`
}

// listeners reads the LISTEN sockets of the network namespace that pid belongs to. No setns needed:
// /proc/<pid>/net is that namespace's view.
func listeners(pid int) ([]listener, error) {
	var out []listener
	for _, proto := range []string{"tcp", "tcp6"} {
		f, err := os.Open(fmt.Sprintf("/proc/%d/net/%s", pid, proto))
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Scan() // header
		for sc.Scan() {
			fl := strings.Fields(sc.Text())
			if len(fl) < 10 || fl[3] != "0A" { // 0A = LISTEN
				continue
			}
			ahex, phex, _ := strings.Cut(fl[1], ":")
			port, _ := strconv.ParseInt(phex, 16, 32)
			out = append(out, listener{Proto: proto, Addr: hexAddr(ahex), Port: int(port), Inode: fl[9]})
		}
		f.Close()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out, nil
}

func hexAddr(h string) string {
	b := make([]byte, len(h)/2)
	for i := range b {
		v, _ := strconv.ParseUint(h[2*i:2*i+2], 16, 8)
		b[i] = byte(v)
	}
	if len(b) == 4 { // /proc prints the 32-bit words in host order
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	}
	return "ipv6:" + h
}

type probeResult struct {
	Status         *procStatus `json:"status"`
	Listeners      []listener  `json:"listeners"`
	ArthasFDs      []string    `json:"arthas_fds"`     // /proc/<pid>/fd targets containing "arthas"
	ArthasThreads  []string    `json:"arthas_threads"` // /proc/<pid>/task/*/comm starting with "arthas" or "as-"
	AllThreadComms []string    `json:"all_thread_comms,omitempty"`
	ArthasMaps     []string    `json:"arthas_maps"` // /proc/<pid>/maps lines mentioning arthas
	JavaSockets    []string    `json:"java_sockets"`
	AttachFiles    []string    `json:"attach_files"`
	SecretFound    []string    `json:"secret_found,omitempty"`
}

func cmdProbe(args []string) (any, error) {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	pid := fs.Int("pid", 0, "host pid of the target JVM")
	secretFile := fs.String("secret-file", "", "file holding a secret to look for in cmdline/environ of every process in the pid namespace")
	allThreads := fs.Bool("all-threads", false, "also list every thread comm")
	_ = fs.Parse(args)
	if *pid == 0 {
		return nil, fmt.Errorf("-pid is required")
	}
	// empty slices, not nil: the JSON consumers take len() of every list
	res := &probeResult{ArthasFDs: []string{}, ArthasThreads: []string{}, ArthasMaps: []string{}, JavaSockets: []string{}, AttachFiles: []string{}}
	var err error
	if res.Status, err = readStatus(*pid); err != nil {
		return nil, err
	}
	if res.Listeners, err = listeners(*pid); err != nil {
		return nil, err
	}

	fds, _ := filepath.Glob(fmt.Sprintf("/proc/%d/fd/*", *pid))
	for _, fd := range fds {
		if t, err := os.Readlink(fd); err == nil && strings.Contains(strings.ToLower(t), "arthas") {
			res.ArthasFDs = append(res.ArthasFDs, filepath.Base(fd)+" -> "+t)
		}
	}

	tasks, _ := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/comm", *pid))
	counts := map[string]int{}
	for _, t := range tasks {
		b, err := os.ReadFile(t)
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(b))
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "arthas") || strings.HasPrefix(lower, "as-") {
			res.ArthasThreads = append(res.ArthasThreads, name)
		}
		counts[name]++
	}
	sort.Strings(res.ArthasThreads)
	if *allThreads {
		for n, c := range counts {
			res.AllThreadComms = append(res.AllThreadComms, fmt.Sprintf("%s x%d", n, c))
		}
		sort.Strings(res.AllThreadComms)
	}

	if mf, err := os.Open(fmt.Sprintf("/proc/%d/maps", *pid)); err == nil {
		sc := bufio.NewScanner(mf)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		seen := map[string]bool{}
		for sc.Scan() {
			if l := sc.Text(); strings.Contains(strings.ToLower(l), "arthas") {
				if fl := strings.Fields(l); len(fl) >= 6 && !seen[fl[5]] {
					seen[fl[5]] = true
					res.ArthasMaps = append(res.ArthasMaps, fl[5])
				}
			}
		}
		mf.Close()
	}

	root := fmt.Sprintf("/proc/%d/root", *pid)
	for _, g := range []string{root + "/tmp/.java_pid*", root + "/tmp/.attach_pid*", fmt.Sprintf("/proc/%d/cwd/.attach_pid*", *pid), fmt.Sprintf("/proc/%d/cwd/.java_pid*", *pid)} {
		m, _ := filepath.Glob(g)
		for _, p := range m {
			if strings.Contains(p, ".java_pid") {
				res.JavaSockets = append(res.JavaSockets, p)
			} else {
				res.AttachFiles = append(res.AttachFiles, p)
			}
		}
	}

	if *secretFile != "" {
		sec, err := os.ReadFile(*secretFile)
		if err != nil {
			return nil, err
		}
		needle := strings.TrimSpace(string(sec))
		myns, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", *pid))
		procs, _ := filepath.Glob("/proc/[0-9]*")
		for _, p := range procs {
			if ns, _ := os.Readlink(p + "/ns/pid"); ns != myns {
				continue
			}
			for _, f := range []string{"cmdline", "environ"} {
				if b, err := os.ReadFile(p + "/" + f); err == nil && strings.Contains(string(b), needle) {
					res.SecretFound = append(res.SecretFound, filepath.Base(p)+"/"+f)
				}
			}
		}
	}
	return res, nil
}

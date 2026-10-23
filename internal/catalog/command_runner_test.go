package catalog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/liubing0806/allowops/internal/params"
)

// Programs that run a command or program text taken from their arguments are
// interpreters: a placeholder reaching them would let the caller run anything.
func TestCommandRunnersRequireAllowInterpreter(t *testing.T) {
	for _, argv := range [][]any{
		{"/usr/bin/watch", "echo"}, {"/usr/bin/ssh", "host", "uptime"}, {"/usr/bin/scp", "a", "host:b"},
		{"/usr/bin/su", "-c", "id", "root"}, {"/usr/sbin/runuser", "-u", "app", "--", "id"},
		{"/usr/bin/setsid", "echo"}, {"/usr/bin/flock", "/tmp/lock", "echo"}, {"/usr/bin/nohup", "echo"},
		{"/usr/bin/systemd-run", "echo"}, {"/usr/bin/unshare", "echo"}, {"/usr/bin/strace", "echo"},
		{"/usr/bin/script", "-c", "id"}, {"/usr/bin/busybox", "sh"}, {"/usr/bin/git", "log"},
		{"/usr/bin/psql", "-c", "select 1"}, {"/usr/bin/mysql", "-e", "select 1"}, {"/usr/bin/sqlite3", "db", "select 1"},
		{"/bin/ksh"}, {"/bin/csh"}, {"/usr/bin/tclsh"},
		{"/usr/bin/find", "/var/log", "-exec", "/bin/echo", ";"}, {"/usr/bin/find", "/var/log", "-okdir", "/bin/echo", ";"},
		{"/usr/bin/tar", "-xf", "a.tar", "--to-command=/bin/sh"}, {"/usr/bin/tar", "--use-compress=/bin/sh", "-xf", "a.tar"},
		{"/usr/bin/tar", "-I", "/bin/sh", "-xf", "a.tar"}, {"/usr/bin/tar", "-xIf", "/bin/sh", "a.tar"},
		{"/usr/bin/tar", "xIf", "/bin/sh", "a.tar"}, {"/usr/bin/tar", "--checkpoint-action=exec=/bin/sh", "-cf", "a.tar", "b"},
		{"/usr/bin/rsync", "-e", "/bin/sh", "a", "b"}, {"/usr/bin/rsync", "-avze", "/bin/sh", "a", "b"},
		{"/usr/bin/rsync", "--rsync-path=/bin/sh", "a", "b"},
		{"/usr/sbin/ip", "netns", "exec", "ns", "/bin/echo"}, {"/usr/sbin/ip", "-batch", "/tmp/commands"},
		{"/usr/bin/timeout", "5", "watch", "echo"}, {"/usr/bin/docker", "exec", "container", "ssh", "host"},
	} {
		a, _ := ParseAction([]byte(validAction))
		a.Exec = argv
		if _, err := ValidateAction(a); err == nil {
			t.Errorf("accepted %q", argv)
		}
		a.AllowInterpreter = true
		if warnings, err := ValidateAction(a); err != nil || len(warnings) == 0 {
			t.Errorf("override %q: warnings=%v err=%v", argv, warnings, err)
		}
	}
	for _, argv := range [][]any{
		{"/usr/bin/find", "/var/log", "-name", "{value}"}, {"/usr/bin/tar", "-tzf", "{value}"}, {"/usr/bin/tar", "tzf", "{value}"},
		{"/usr/bin/rsync", "-a", "--dry-run", "a", "b"}, {"/usr/sbin/ip", "addr", "show", "{value}"},
		{"/usr/bin/crontab", "-l", "-u", "{value}"},
	} {
		a, _ := ParseAction([]byte(validAction))
		a.Exec = argv
		if _, err := ValidateAction(a); err != nil {
			t.Errorf("%q: %v", argv, err)
		}
	}
	// Enum values are checked once rendered.
	if err := CheckCommand([]string{"/usr/bin/find", "/var/log", "-exec", "/bin/echo", ";"}, false); err == nil {
		t.Error("accepted rendered find -exec")
	}
}

// The host resolves symlinks, so a runner under another name is still one.
func TestCommandRunnerAliasOnHost(t *testing.T) {
	echo, err := os.ReadFile("/bin/echo")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	runner := filepath.Join(dir, "watch")
	if err := os.WriteFile(runner, echo, 0755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(runner, alias); err != nil {
		t.Fatal(err)
	}
	a, _ := ParseAction([]byte(validAction))
	a.Exec = []any{alias, "echo"}
	if status := CheckHost(a); status.Supported {
		t.Fatal("accepted alias to a command runner")
	}
}

// Under allow_interpreter the program text stays signed: placeholders may only
// supply arguments after it, never options, the program, or a runner's command.
func TestInterpreterProgramTextFixed(t *testing.T) {
	zero := int64(0)
	defs := map[string]params.Definition{
		"value": {Type: params.String, Description: "value", MaxLen: 64},
		"mode":  {Type: params.Enum, Description: "mode", Values: []string{"-e", "a"}},
		"safe":  {Type: params.Enum, Description: "safe", Values: []string{"a", "b"}},
		"n":     {Type: params.Int, Description: "n"},
		"count": {Type: params.Int, Description: "count", Min: &zero},
	}
	for _, argv := range [][]any{
		{"/bin/bash", "-c", "{value}"}, {"/bin/bash", "{value}"}, {"/bin/bash", "-o", "{value}", "-c", "x"},
		{"/bin/bash", "-c", "-o", "pipefail", "{value}"}, {"/bin/sh", "-s", "{value}"},
		{"/usr/bin/python3", "-c", "{value}"}, {"/usr/bin/python3", "-m", "{value}"},
		{"/usr/bin/python3", "-W", "ignore", "{value}"}, {"/usr/bin/python3", "-X", "{value}", "-c", "x"},
		{"/usr/bin/python3", "--unknown", "-c", "x", "{value}"}, {"/usr/bin/python3", []any{"-W", "ignore"}, "{value}"},
		{"/usr/bin/perl", "-e", "x", "-e", "{value}"}, {"/usr/bin/perl", "-ne", "{value}"}, {"/usr/bin/perl", "-e", "x", "-I", "{value}"},
		{"/usr/bin/perl", "-e", "x", "{mode}"}, {"/usr/bin/perl", "-e", "x", "{n}"},
		{"/usr/bin/node", "--eval", "{value}"}, {"/usr/bin/node", "-p", "{value}"}, {"/usr/bin/ruby", "-e", "{value}"},
		{"/usr/bin/php", "-r", "{value}"}, {"/usr/bin/lua", "-e", "x", "{value}"},
		{"/usr/bin/awk", "{value}"}, {"/usr/bin/awk", "-F", ":", "{value}"}, {"/usr/bin/gawk", "--source", "{value}"},
		{"/usr/bin/sed", "{value}"}, {"/usr/bin/sed", "-n", "-e", "{value}"}, {"/usr/bin/sed", "-e", "p", "-e", "{value}"},
		{"/usr/bin/docker", "exec", "container", "sh", "-c", "{value}"}, {"/usr/bin/timeout", "5", "python3", "-c", "{value}"},
		{"/usr/bin/ssh", "{value}", "uptime"}, {"/usr/bin/watch", "{value}"}, {"/usr/bin/git", "-C", "{value}", "status"},
		{"/usr/bin/find", "{value}", "-exec", "/bin/echo", ";"}, {"/usr/bin/psql", "-c", "{value}"},
	} {
		a, _ := ParseAction([]byte(validAction))
		a.Exec = argv
		a.Params = defs
		a.AllowInterpreter = true
		if _, err := ValidateAction(a); err == nil {
			t.Errorf("accepted %q", argv)
		}
	}
	for _, argv := range [][]any{
		{"/bin/bash", "-c", `echo "$1"`, "_", "{value}"}, {"/bin/bash", "-euo", "pipefail", "-c", "x", "_", "{value}"},
		{"/bin/bash", "/opt/x.sh", "{value}"}, {"/usr/bin/python3", "-I", "-c", "x", "{value}"},
		{"/usr/bin/python3", "-m", "json.tool", "{value}"}, {"/usr/bin/perl", "-ne", "print", "{value}"},
		{"/usr/bin/perl", "-e", "x", "--", "{value}"}, {"/usr/bin/perl", "-e", "x", "{safe}", "{count}"},
		{"/usr/bin/node", "--eval=x", "{value}"}, {"/usr/bin/ruby", "-e", "x", "{value}"}, {"/usr/bin/php", "-r", "x", "{value}"},
		{"/usr/bin/lua", "/opt/x.lua", "{value}"}, {"/usr/bin/awk", "-F:", "{ print $1 }", "{value}"},
		{"/usr/bin/sed", "-n", "p", "{value}"}, {"/usr/bin/sed", "-e", "p", "--", "{value}"},
		{"/usr/bin/docker", "exec", "container", "python3", "-c", "x", "{value}"},
		{"/bin/bash", "-c", "x", "--unknown"}, {"/usr/bin/ssh", "host", "uptime"},
	} {
		a, _ := ParseAction([]byte(validAction))
		a.Exec = argv
		a.Params = defs
		a.AllowInterpreter = true
		if _, err := ValidateAction(a); err != nil {
			t.Errorf("%q: %v", argv, err)
		}
	}
}

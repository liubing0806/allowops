package attack

import (
	"testing"

	"github.com/liubing0806/allowops/internal/catalog"
)

func TestXargsExecutableReplacement(t *testing.T) {
	for _, argv := range [][]any{
		{"/usr/bin/xargs", "-I{}", "{}"},
		{"/usr/bin/xargs", "-I%", "/usr/bin/docker", "%", "container", "sh"},
		{"/usr/bin/xargs", "--replace", "sh"},
		{"/usr/bin/xargs", "--eof", "sh"},
		{"/usr/bin/nsenter", "--env", "sh", "echo"},
		{"/usr/bin/nsenter", "--setuid", "sh", "echo"},
		{"/usr/bin/nsenter", "--setgid", "sh", "echo"},
		{"/usr/bin/nsenter", "--join-cgroup", "sh", "echo"},
		{"/usr/bin/xargs", "--replace=%", "/bin/%"},
		{"/usr/bin/xargs", "-I", "%", "/usr/bin/env", "%", "echo"},
		{"/usr/bin/xargs", "-I", "%", "/usr/bin/docker", "exec", "%", "container", "echo"},
	} {
		if _, err := catalog.ValidateAction(attackAction(argv)); err == nil {
			t.Errorf("accepted executable replacement %q", argv)
		}
	}
	a := attackAction([]any{"/usr/bin/xargs", "-I{}", "/bin/echo", "{}"})
	if _, err := catalog.ValidateAction(a); err != nil {
		t.Fatalf("safe argument replacement: %v", err)
	}
}

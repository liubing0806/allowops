package redact

import "testing"

// Short password options as elements of a JSON argument array, as printed by
// docker inspect (Cmd, Args, Healthcheck.Test) and container runtimes.
func TestShortPasswordOptionsInArgumentArrays(t *testing.T) {
	r := builtinOnly(t)
	checkSecretCases(t, r, []secretCase{
		{`["curl","-u","a:LEAKA1","http://h"]`, "LEAKA1"},
		{`["curl", "-sS", "--user", "a:LEAKA2", "http://h"]`, "LEAKA2"},
		{`["curl","--proxy-user","p:LEAKA3","http://h"]`, "LEAKA3"},
		{`["curl","-ua:LEAKA4","http://h"]`, "LEAKA4"},
		{`"Test": ["CMD", "redis-cli", "-a", "LEAKA5", "ping"]`, "LEAKA5"},
		{`["redis-cli","-aLEAKA6","ping"]`, "LEAKA6"},
		{`["sshpass","-p","LEAKA7","ssh","h"]`, "LEAKA7"},
	})
	for _, line := range []string{
		`["docker","exec","-u","1000:1000","app","ls"]`,
		`["curl","-u","admin","http://h"]`,
		`["ps","-a"]`,
	} {
		if got := r.Line(line); got != line {
			t.Errorf("changed %q => %q", line, got)
		}
	}
}

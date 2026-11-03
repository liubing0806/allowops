package arthas

import (
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// sourceCommands is the set of @Name values of the commands registered by
// BuiltinCommandPack in Arthas 4.3.5 (auth and classloader-metaspace are
// declared with a constant and a fully qualified annotation, so a plain search
// for @Name("...") misses them), plus groovy, whose class exists but is not
// registered. It is deliberately a second copy of the list in agent.go.
var sourceCommands = strings.Fields(`auth base64 cat classloader classloader-metaspace cls dashboard dump echo getstatic
grep groovy heapdump help history jad jfr july jvm keymap line logger mbean mc memory monitor ognl options
perfcounter profiler pwd redefine reset retransform sc session sm stack stop sysenv sysprop tee thanks thread
trace tt version vmoption vmtool watch`)

func TestAllCommandsMatchesSource(t *testing.T) {
	got := AllCommands()
	want := append([]string(nil), sourceCommands...)
	sort.Strings(want)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("AllCommands() = %v\nwant %v", got, want)
	}
	got[0] = "changed"
	if AllCommands()[0] == "changed" {
		t.Fatal("AllCommands returns the internal slice")
	}
}

func TestDisabledCommands(t *testing.T) {
	got, err := DisabledCommands([]string{"thread", "version"})
	if err != nil {
		t.Fatal(err)
	}
	if !sort.StringsAreSorted(got) {
		t.Fatalf("not sorted: %v", got)
	}
	set := map[string]bool{}
	for _, name := range got {
		set[name] = true
	}
	for _, name := range []string{"thread", "version", "reset", "stop"} {
		if set[name] {
			t.Errorf("%s is disabled, want enabled", name)
		}
	}
	for _, name := range []string{"ognl", "watch", "auth", "classloader-metaspace", "dashboard", "sysenv", "vmtool", "mc"} {
		if !set[name] {
			t.Errorf("%s is enabled, want disabled", name)
		}
	}
	if len(got) != len(sourceCommands)-4 {
		t.Errorf("len = %d, want %d", len(got), len(sourceCommands)-4)
	}
}

func TestDisabledCommandsRejectsUnknownName(t *testing.T) {
	for _, name := range []string{"", "Thread", "thread,ognl", "nosuchcommand", "thread -n 1"} {
		if _, err := DisabledCommands([]string{name}); err == nil {
			t.Errorf("DisabledCommands(%q) succeeded", name)
		}
	}
}

func TestNewPassword(t *testing.T) {
	re := regexp.MustCompile(`^[A-Za-z0-9]{32}$`)
	seen := map[string]bool{}
	for range 50 {
		pw, err := NewPassword()
		if err != nil {
			t.Fatal(err)
		}
		if !re.MatchString(pw) {
			t.Fatalf("password %q does not match %s", pw, re)
		}
		if seen[pw] {
			t.Fatalf("password %q repeated", pw)
		}
		seen[pw] = true
	}
}

func goodConfig() AgentConfig {
	return AgentConfig{
		AgentJar:       "/usr/share/allowops/arthas/4.3.5/arthas-agent.jar",
		CoreJar:        "/usr/share/allowops/arthas/4.3.5/arthas-core.jar",
		HTTPPort:       18563,
		Password:       "abcdefghijklmnopABCDEFGHIJKLMNOP0123456789"[:32],
		Enabled:        []string{"version"},
		SessionTimeout: 90 * time.Second,
	}
}

func TestOptions(t *testing.T) {
	c := goodConfig()
	got, err := c.Options()
	if err != nil {
		t.Fatal(err)
	}
	disabled := make([]string, 0, len(sourceCommands))
	for _, name := range sourceCommands {
		if name != "version" && name != "reset" && name != "stop" {
			disabled = append(disabled, name)
		}
	}
	sort.Strings(disabled)
	want := "/usr/share/allowops/arthas/4.3.5/arthas-core.jar;telnetPort=-1;httpPort=18563;ip=127.0.0.1;" +
		"password=abcdefghijklmnopABCDEFGHIJKLMNOP;localConnectionNonAuth=false;" +
		"disabledCommands=" + strings.Join(disabled, ",") + ";sessionTimeout=90"
	if got != want {
		t.Fatalf("Options() =\n%s\nwant\n%s", got, want)
	}
	if strings.Contains(got, "mcpEndpoint") {
		t.Error("options must not mention mcpEndpoint: an empty value is dropped by Arthas")
	}
	arg, err := c.Argument()
	if err != nil {
		t.Fatal(err)
	}
	if arg != c.AgentJar+"="+want {
		t.Fatalf("Argument() = %q", arg)
	}
}

func TestOptionsRoundsSessionTimeoutUp(t *testing.T) {
	c := goodConfig()
	c.SessionTimeout = 1500 * time.Millisecond
	got, err := c.Options()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got, ";sessionTimeout=2") {
		t.Fatalf("Options() = %q", got)
	}
}

func TestOptionsRejectsInvalidConfig(t *testing.T) {
	cases := map[string]func(*AgentConfig){
		"percent in core jar":      func(c *AgentConfig) { c.CoreJar = "/opt/a%41/arthas-core.jar" },
		"plus in core jar":         func(c *AgentConfig) { c.CoreJar = "/opt/a+b/arthas-core.jar" },
		"semicolon in core jar":    func(c *AgentConfig) { c.CoreJar = "/opt/a;b/arthas-core.jar" },
		"equals in core jar":       func(c *AgentConfig) { c.CoreJar = "/opt/a=b/arthas-core.jar" },
		"backslash in core jar":    func(c *AgentConfig) { c.CoreJar = `/opt/a\b/arthas-core.jar` },
		"newline in core jar":      func(c *AgentConfig) { c.CoreJar = "/opt/a\nb/arthas-core.jar" },
		"tab in core jar":          func(c *AgentConfig) { c.CoreJar = "/opt/a\tb/arthas-core.jar" },
		"NUL in core jar":          func(c *AgentConfig) { c.CoreJar = "/opt/a\x00b/arthas-core.jar" },
		"DEL in core jar":          func(c *AgentConfig) { c.CoreJar = "/opt/a\x7fb/arthas-core.jar" },
		"empty core jar":           func(c *AgentConfig) { c.CoreJar = "" },
		"relative core jar":        func(c *AgentConfig) { c.CoreJar = "arthas-core.jar" },
		"percent in agent jar":     func(c *AgentConfig) { c.AgentJar = "/opt/a%41/arthas-agent.jar" },
		"equals in agent jar":      func(c *AgentConfig) { c.AgentJar = "/opt/a=b/arthas-agent.jar" },
		"newline in agent jar":     func(c *AgentConfig) { c.AgentJar = "/opt/a\nb/arthas-agent.jar" },
		"empty agent jar":          func(c *AgentConfig) { c.AgentJar = "" },
		"empty password":           func(c *AgentConfig) { c.Password = "" },
		"short password":           func(c *AgentConfig) { c.Password = "abc123" },
		"plus in password":         func(c *AgentConfig) { c.Password = "abcdefghijklmnop+bcdefghijklmnop" },
		"percent in password":      func(c *AgentConfig) { c.Password = "abcdefghijklmnop%41cdefghijklmnop" },
		"semicolon in password":    func(c *AgentConfig) { c.Password = "abcdefghijklmnop;bcdefghijklmnop" },
		"equals in password":       func(c *AgentConfig) { c.Password = "abcdefghijklmnop=bcdefghijklmnop" },
		"space in password":        func(c *AgentConfig) { c.Password = "abcdefghijklmnop bcdefghijklmnop" },
		"port zero":                func(c *AgentConfig) { c.HTTPPort = 0 },
		"port negative":            func(c *AgentConfig) { c.HTTPPort = -1 },
		"port too large":           func(c *AgentConfig) { c.HTTPPort = 65536 },
		"zero session timeout":     func(c *AgentConfig) { c.SessionTimeout = 0 },
		"negative session timeout": func(c *AgentConfig) { c.SessionTimeout = -time.Second },
		"unknown enabled command":  func(c *AgentConfig) { c.Enabled = []string{"nosuchcommand"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := goodConfig()
			mutate(&c)
			if got, err := c.Options(); err == nil {
				t.Fatalf("Options() = %q, want an error", got)
			}
			if got, err := c.Argument(); err == nil {
				t.Fatalf("Argument() = %q, want an error", got)
			}
		})
	}
}

func TestCheckArgumentLength(t *testing.T) {
	agent := "/opt/arthas-agent.jar"
	atLimit := strings.Repeat("x", MaxArgumentBytes-len(agent)-1)
	if err := CheckArgumentLength(agent, atLimit); err != nil {
		t.Fatalf("1024 bytes rejected: %v", err)
	}
	if err := CheckArgumentLength(agent, atLimit+"x"); err == nil {
		t.Fatal("1025 bytes accepted")
	}
	// The limit counts bytes, not characters.
	multibyte := strings.Repeat("é", (MaxArgumentBytes-len(agent)-1)/2+1)
	if err := CheckArgumentLength(agent, multibyte); err == nil {
		t.Fatal("a string of 1025 bytes and fewer characters was accepted")
	}
}

func TestArgumentRejectsOversizedOptions(t *testing.T) {
	c := goodConfig()
	c.CoreJar = "/" + strings.Repeat("d", MaxArgumentBytes)
	if got, err := c.Argument(); err == nil {
		t.Fatalf("Argument() accepted %d bytes", len(got))
	}
}

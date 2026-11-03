package arthas

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

var testPolicy = Policy{SyspropKeys: []string{"java.version", "user.dir", "file.encoding"}}

func TestBuildCommands(t *testing.T) {
	cases := []struct {
		name string
		req  Request
		text string
		cmd  string
		pre  []PreCheck
	}{
		{"dashboard", Request{Kind: KindDashboard}, "dashboard -n 1", "dashboard", nil},
		{"thread top 1", Request{Kind: KindThreadTop, Top: 1}, "thread -n 1", "thread", nil},
		{"thread top 10", Request{Kind: KindThreadTop, Top: 10}, "thread -n 10", "thread", nil},
		{"thread blocking", Request{Kind: KindThreadBlocking}, "thread -b", "thread", []PreCheck{PreCheckThreadCount}},
		{"thread info", Request{Kind: KindThreadInfo, ThreadID: 49}, "thread 49", "thread", nil},
		{"memory", Request{Kind: KindMemory}, "memory", "memory", nil},
		{"jvm", Request{Kind: KindJVM}, "jvm", "jvm", nil},
		{"class info", Request{Kind: KindClassInfo, Class: "demo.HotService"}, "sc -d demo.HotService", "sc", nil},
		{"class info nested", Request{Kind: KindClassInfo, Class: "java.util.Map$Entry"}, "sc -d java.util.Map$Entry", "sc", nil},
		{"class info default package", Request{Kind: KindClassInfo, Class: "Main"}, "sc -d Main", "sc", nil},
		{"method info", Request{Kind: KindMethodInfo, Class: "demo.HotService", Method: "work"}, "sm -d demo.HotService work", "sm", nil},
		{"method info all methods", Request{Kind: KindMethodInfo, Class: "demo.HotService"}, "sm -d demo.HotService", "sm", nil},
		{"method info dollar", Request{Kind: KindMethodInfo, Class: "a.B$C", Method: "lambda$main$0"}, "sm -d a.B$C lambda$main$0", "sm", nil},
		{"classloader tree", Request{Kind: KindClassLoaderTree}, "classloader -t", "classloader", nil},
		{"classloader list", Request{Kind: KindClassLoaderList}, "classloader -l", "classloader", nil},
		{"logger", Request{Kind: KindLogger}, "logger", "logger", nil},
		{"sysprop", Request{Kind: KindSysprop, Key: "java.version"}, "sysprop java.version", "sysprop", nil},
		{"version", Request{Kind: KindVersion}, "version", "version", nil},
	}
	seen := map[Kind]bool{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Build(c.req, testPolicy)
			if err != nil {
				t.Fatal(err)
			}
			if got.Text != c.text || got.Name != c.cmd || got.Kind != c.req.Kind {
				t.Fatalf("Build() = %+v, want text %q name %q", got, c.text, c.cmd)
			}
			if got.ExecTimeout != DefaultExecTimeout {
				t.Errorf("ExecTimeout = %s, want %s", got.ExecTimeout, DefaultExecTimeout)
			}
			if len(got.PreChecks) != len(c.pre) || (len(c.pre) == 1 && got.PreChecks[0] != c.pre[0]) {
				t.Errorf("PreChecks = %v, want %v", got.PreChecks, c.pre)
			}
		})
		seen[c.req.Kind] = true
	}
	for _, k := range Kinds() {
		if !seen[k] {
			t.Errorf("kind %s has no case", k)
		}
	}
	if len(Kinds()) != 12 {
		t.Errorf("Kinds() = %v, want 12 kinds", Kinds())
	}
}

// logger is paused: Build still makes the command, but it is not offered (decision A69).
func TestLoggerIsPaused(t *testing.T) {
	reason, ok := Paused(KindLogger)
	if !ok || !strings.Contains(reason, "class loader") || !strings.Contains(reason, "12 MiB") {
		t.Errorf("Paused(logger) = %q, %v", reason, ok)
	}
	for _, k := range Kinds() {
		if k == KindLogger {
			t.Error("Kinds() offers logger")
		}
		if reason, ok := Paused(k); ok {
			t.Errorf("offered kind %s is paused: %s", k, reason)
		}
	}
	if _, ok := Paused("ognl"); ok {
		t.Error("an unknown kind is reported as paused")
	}
}

func TestBuildExecTimeout(t *testing.T) {
	for _, d := range []time.Duration{time.Second, 5 * time.Second, MaxExecTimeout} {
		got, err := Build(Request{Kind: KindMemory}, Policy{ExecTimeout: d})
		if err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		if got.ExecTimeout != d {
			t.Errorf("ExecTimeout = %s, want %s", got.ExecTimeout, d)
		}
	}
	for _, d := range []time.Duration{-time.Second, MaxExecTimeout + time.Millisecond, time.Hour} {
		if _, err := Build(Request{Kind: KindMemory}, Policy{ExecTimeout: d}); err == nil {
			t.Errorf("ExecTimeout %s accepted", d)
		}
	}
}

// hostile holds argument values that must never reach an Arthas command line.
var hostile = []string{
	"", " ", "a b", " a", "a ", "a;b", "a;ognl 1", "a|b", "a|grep x", "a>b", "a>>b", "a<b", "a&b", "a&&b",
	"a\nb", "a\rb", "a\tb", "a\x00b", "a\x7fb", `a"b`, `"a"`, "a'b", "'a'", "a`b`", "a$(id)", "a${x}", "a#b", "a@b",
	"@java.lang.Runtime@getRuntime()", "java.lang.Runtime@getRuntime().exec('id')", "a{b", "a}b", "{a}", "a*b", "*", "a?b",
	"a[b]", "a(b)", "a,b", "a:b", "a/b", `a\b`, "a!b", "a~b", "a=b", "a%41", "a+b", "-E", "-x", "-n", "--help", "-", "--", "-1", "-b",
	".a", "a.", "a..b", "1a", "a.1b", "类", "a.类", strings.Repeat("a", 300),
}

func TestBuildRejectsHostileClassNames(t *testing.T) {
	for _, h := range hostile {
		for _, kind := range []Kind{KindClassInfo, KindMethodInfo} {
			if got, err := Build(Request{Kind: kind, Class: h}, testPolicy); err == nil {
				t.Errorf("%s accepted class %q as %q", kind, h, got.Text)
			}
		}
	}
}

func TestBuildRejectsHostileMethodNames(t *testing.T) {
	for _, h := range append([]string{"<init>", "<clinit>", "a.b", "a$b.c"}, hostile...) {
		if h == "" {
			continue // an empty method name means "all methods"
		}
		if got, err := Build(Request{Kind: KindMethodInfo, Class: "demo.HotService", Method: h}, testPolicy); err == nil {
			t.Errorf("accepted method %q as %q", h, got.Text)
		}
	}
}

func TestBuildRejectsSyspropKeysOutsideThePolicy(t *testing.T) {
	for _, h := range append([]string{"java.home", "user.name", "JAVA.VERSION", "java.version ", " java.version", "java.version.x", "java"}, hostile...) {
		if got, err := Build(Request{Kind: KindSysprop, Key: h}, testPolicy); err == nil {
			t.Errorf("accepted key %q as %q", h, got.Text)
		}
	}
	if _, err := Build(Request{Kind: KindSysprop, Key: "java.version"}, Policy{}); err == nil {
		t.Error("sysprop without an allowlist succeeded")
	}
}

func TestBuildRejectsUnsafeAllowlistEntries(t *testing.T) {
	for _, h := range hostile {
		pol := Policy{SyspropKeys: []string{h}}
		if got, err := Build(Request{Kind: KindSysprop, Key: h}, pol); err == nil {
			t.Errorf("allowlist entry %q produced %q", h, got.Text)
		}
		// A bad entry is a configuration error even when another key is requested.
		if _, err := Build(Request{Kind: KindSysprop, Key: "java.version"}, Policy{SyspropKeys: []string{"java.version", h}}); err == nil && h != "" {
			t.Errorf("allowlist entry %q was not rejected", h)
		}
	}
}

func TestBuildRejectsInvalidNumbers(t *testing.T) {
	for _, n := range []int{-1, 0, 11, 100, 1 << 30} {
		if got, err := Build(Request{Kind: KindThreadTop, Top: n}, testPolicy); err == nil {
			t.Errorf("top %d accepted as %q", n, got.Text)
		}
	}
	for _, id := range []int64{-1, 0, -9223372036854775808} {
		if got, err := Build(Request{Kind: KindThreadInfo, ThreadID: id}, testPolicy); err == nil {
			t.Errorf("thread id %d accepted as %q", id, got.Text)
		}
	}
	if got, err := Build(Request{Kind: KindThreadInfo, ThreadID: 9223372036854775807}, testPolicy); err != nil || got.Text != "thread 9223372036854775807" {
		t.Errorf("largest thread id: %q, %v", got.Text, err)
	}
}

func TestBuildRejectsFieldsOfOtherKinds(t *testing.T) {
	cases := []Request{
		{Kind: KindMemory, Class: "a.B"},
		{Kind: KindMemory, Method: "m"},
		{Kind: KindMemory, Key: "java.version"},
		{Kind: KindMemory, Top: 1},
		{Kind: KindMemory, ThreadID: 1},
		{Kind: KindThreadTop, Top: 1, ThreadID: 1},
		{Kind: KindThreadTop, Top: 1, Class: "a.B"},
		{Kind: KindThreadInfo, ThreadID: 1, Top: 1},
		{Kind: KindThreadBlocking, Top: 1},
		{Kind: KindClassInfo, Class: "a.B", Method: "m"},
		{Kind: KindClassInfo, Class: "a.B", Key: "java.version"},
		{Kind: KindMethodInfo, Class: "a.B", Key: "java.version"},
		{Kind: KindSysprop, Key: "java.version", Class: "a.B"},
		{Kind: KindDashboard, Top: 5},
		{Kind: KindLogger, Class: "a.B"},
	}
	for _, req := range cases {
		if got, err := Build(req, testPolicy); err == nil {
			t.Errorf("%+v accepted as %q", req, got.Text)
		}
	}
}

func TestBuildRejectsUnknownKinds(t *testing.T) {
	for _, k := range []Kind{"", "ognl", "watch", "thread", "sc", "sysprop ", "THREAD_TOP", "dashboard -n 1", "reset", "stop", "heapdump"} {
		if got, err := Build(Request{Kind: k, Top: 1, ThreadID: 1, Class: "a.B", Key: "java.version"}, testPolicy); err == nil {
			t.Errorf("kind %q accepted as %q", k, got.Text)
		}
	}
}

// commandForm lists every text Build may return; anything else is a bug.
var commandForm = regexp.MustCompile(`^(` +
	`dashboard -n 1|thread -n (10|[1-9])|thread -b|thread [1-9][0-9]*|memory|jvm|classloader -[tl]|logger|version|` +
	`sc -d [A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*|` +
	`sm -d [A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*( [A-Za-z_$][A-Za-z0-9_$]*)?|` +
	`sysprop (java\.version|user\.dir|file\.encoding))$`)

func FuzzBuildOnlyReturnsFixedForms(f *testing.F) {
	for _, h := range hostile {
		f.Add(h, h, h, 1, int64(1), uint8(0))
	}
	f.Add("demo.HotService", "work", "java.version", 5, int64(49), uint8(3))
	kinds := Kinds()
	f.Fuzz(func(t *testing.T, class, method, key string, top int, id int64, which uint8) {
		kind := kinds[int(which)%len(kinds)]
		got, err := Build(Request{Kind: kind, Class: class, Method: method, Key: key, Top: top, ThreadID: id}, testPolicy)
		if err != nil {
			return
		}
		if !commandForm.MatchString(got.Text) {
			t.Fatalf("Build(%q, %q, %q, %d, %d) returned %q", class, method, key, top, id, got.Text)
		}
		if got.ExecTimeout <= 0 || got.ExecTimeout > MaxExecTimeout {
			t.Fatalf("ExecTimeout = %s", got.ExecTimeout)
		}
	})
}

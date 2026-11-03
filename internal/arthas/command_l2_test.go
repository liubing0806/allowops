package arthas

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// l2Policy allows two packages; com. is broad on purpose, to show that the forbidden packages
// under it stay forbidden.
var l2Policy = Policy{ClassPrefixes: []string{"demo.", "com."}}

// validL2 returns a request of kind that Build accepts.
func validL2(kind Kind) Request {
	req := Request{Kind: kind, Class: "demo.HotService", Method: "work", Count: 1}
	switch kind {
	case KindWatch:
		req.Express, req.Expand = "params,returnObj", 1
	case KindMonitor:
		req.Cycle = 5
	case KindJad:
		req.Method, req.Count = "", 0
	}
	return req
}

var enhancingKinds = []Kind{KindWatch, KindTrace, KindStack, KindMonitor}
var l2Kinds = append(slices.Clone(enhancingKinds), KindJad)

func TestBuildL2Commands(t *testing.T) {
	sub := "options disable-sub-class true"
	cases := []struct {
		name    string
		req     Request
		pol     Policy
		text    string
		setup   []string
		enhance time.Duration
		methods int
		enabled []string
	}{
		{"watch", Request{Kind: KindWatch, Class: "demo.HotService", Method: "work", Express: "params,returnObj", Expand: 2, Count: 3},
			l2Policy, "watch demo.HotService work {params,returnObj} -n 3 -x 2 -m 1 --timeout 30",
			[]string{sub, "options object-size-limit 8192"}, 30 * time.Second, 5, []string{"watch", "options"}},
		{"watch condition", Request{Kind: KindWatch, Class: "demo.HotService", Method: "work", Express: "params,returnObj,throwExp", Expand: 1, Count: 5, MinCost: 200},
			Policy{ClassPrefixes: []string{"demo."}, Enhance: 10 * time.Second, MaxMethods: 2, ObjectSizeLimit: 65536},
			"watch demo.HotService work {params,returnObj,throwExp} #cost>200 -n 5 -x 1 -m 1 --timeout 10",
			[]string{sub, "options object-size-limit 65536"}, 10 * time.Second, 2, []string{"watch", "options"}},
		{"watch throwExp", Request{Kind: KindWatch, Class: "demo.a.B$C", Method: "lambda$run$0", Express: "throwExp", Expand: 1, Count: 1},
			l2Policy, "watch demo.a.B$C lambda$run$0 {throwExp} -n 1 -x 1 -m 1 --timeout 30",
			[]string{sub, "options object-size-limit 8192"}, 30 * time.Second, 5, []string{"watch", "options"}},
		{"trace", Request{Kind: KindTrace, Class: "com.example.Api", Method: "handle", Count: 2, MinCost: 1},
			l2Policy, "trace com.example.Api handle #cost>1 -n 2 -m 1 --timeout 30", []string{sub}, 30 * time.Second, 5, []string{"trace", "options"}},
		{"stack", Request{Kind: KindStack, Class: "demo.HotService", Method: "work", Count: 1},
			Policy{ClassPrefixes: []string{"demo."}, Enhance: time.Second}, "stack demo.HotService work -n 1 -m 1 --timeout 1", []string{sub}, time.Second, 5, []string{"stack", "options"}},
		{"monitor", Request{Kind: KindMonitor, Class: "demo.HotService", Method: "work", Count: 5, Cycle: 5, MinCost: 10},
			l2Policy, "monitor demo.HotService work #cost>10 -c 5 -n 5 -m 1 --timeout 30", []string{sub}, 30 * time.Second, 5, []string{"monitor", "options"}},
		{"monitor longest cycle", Request{Kind: KindMonitor, Class: "demo.HotService", Method: "work", Count: 1, Cycle: 29},
			l2Policy, "monitor demo.HotService work -c 29 -n 1 -m 1 --timeout 30", []string{sub}, 30 * time.Second, 5, []string{"monitor", "options"}},
		{"jad", Request{Kind: KindJad, Class: "demo.HotService"}, l2Policy, "jad --source-only demo.HotService", nil, 0, 0, []string{"jad"}},
		{"jad method", Request{Kind: KindJad, Class: "demo.HotService", Method: "work"}, l2Policy, "jad --source-only demo.HotService work", nil, 0, 0, []string{"jad"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Build(c.req, c.pol)
			if err != nil {
				t.Fatal(err)
			}
			if got.Text != c.text || got.Name != string(c.req.Kind) || got.Level != 2 {
				t.Fatalf("Build() = %+v, want text %q", got, c.text)
			}
			if !slices.Equal(got.Setup, c.setup) || got.Enhance != c.enhance || got.MaxMethods != c.methods {
				t.Errorf("Setup %q, Enhance %s, MaxMethods %d; want %q, %s, %d", got.Setup, got.Enhance, got.MaxMethods, c.setup, c.enhance, c.methods)
			}
			if !slices.Equal(got.Enabled(), c.enabled) {
				t.Errorf("Enabled() = %q, want %q", got.Enabled(), c.enabled)
			}
			if !slices.Equal(got.PreChecks, []PreCheck{PreCheckCPU}) {
				t.Errorf("PreChecks = %v", got.PreChecks)
			}
		})
	}
}

func TestKindLevel(t *testing.T) {
	for _, k := range Kinds() {
		want := 1
		if slices.Contains(l2Kinds, k) {
			want = 2
		}
		if k.Level() != want || k.Enhances() != slices.Contains(enhancingKinds, k) {
			t.Errorf("%s: level %d, enhances %v", k, k.Level(), k.Enhances())
		}
	}
	for _, k := range l2Kinds {
		got, err := Build(validL2(k), l2Policy)
		if err != nil || got.Level != k.Level() || (got.Enhance > 0) != k.Enhances() {
			t.Errorf("%s: built %+v, %v", k, got, err)
		}
	}
}

func TestBuildL1CommandsAreLevel1(t *testing.T) {
	for _, k := range Kinds() {
		if slices.Contains(l2Kinds, k) {
			continue
		}
		req := Request{Kind: k}
		switch k {
		case KindThreadTop:
			req.Top = 1
		case KindThreadInfo:
			req.ThreadID = 1
		case KindClassInfo, KindMethodInfo:
			req.Class = "demo.A"
		case KindSysprop:
			req.Key = "java.version"
		}
		got, err := Build(req, testPolicy)
		if err != nil {
			t.Fatal(err)
		}
		if got.Level != 1 || got.Enhance != 0 || got.Setup != nil || !slices.Equal(got.Enabled(), []string{got.Name}) {
			t.Errorf("%s: %+v", k, got)
		}
	}
}

func TestBuildL2RejectsHostileClassNames(t *testing.T) {
	for _, h := range hostile {
		for _, kind := range l2Kinds {
			req := validL2(kind)
			req.Class = h
			if got, err := Build(req, l2Policy); err == nil {
				t.Errorf("%s accepted class %q as %q", kind, h, got.Text)
			}
			// The hostile text after an allowed prefix.
			req.Class = "demo." + h
			if got, err := Build(req, l2Policy); err == nil && !classNameRE.MatchString(h) {
				t.Errorf("%s accepted class %q as %q", kind, req.Class, got.Text)
			}
		}
	}
}

func TestBuildL2RejectsHostileMethodNames(t *testing.T) {
	for _, h := range append([]string{"<init>", "<clinit>", "a.b", "a$b.c", "work*", "wo?k"}, hostile...) {
		for _, kind := range l2Kinds {
			if h == "" && kind == KindJad {
				continue // jad without a method decompiles the whole class
			}
			req := validL2(kind)
			req.Method = h
			if got, err := Build(req, l2Policy); err == nil {
				t.Errorf("%s accepted method %q as %q", kind, h, got.Text)
			}
		}
	}
}

func TestBuildL2RejectsForbiddenPackages(t *testing.T) {
	classes := []string{
		"java.lang.String", "java.arthas.SpyAPI", "javax.servlet.http.HttpServlet", "jdk.internal.misc.Unsafe", "sun.misc.Unsafe",
		"com.sun.net.httpserver.HttpServer", "com.taobao.arthas.core.server.ArthasBootstrap", "com.alibaba.arthas.deps.ch.qos.logback.Logger",
	}
	broad := Policy{ClassPrefixes: []string{"com.", "demo."}}
	for _, class := range classes {
		for _, kind := range l2Kinds {
			req := validL2(kind)
			req.Class = class
			if got, err := Build(req, broad); err == nil || !strings.Contains(err.Error(), "never enhanced") {
				t.Errorf("%s accepted class %s as %q (%v)", kind, class, got.Text, err)
			}
		}
	}
	// com.example is under com. and not forbidden.
	req := validL2(KindWatch)
	req.Class = "com.example.Service"
	if _, err := Build(req, broad); err != nil {
		t.Errorf("com.example.Service: %v", err)
	}
}

func TestBuildL2RequiresAnAllowedPrefix(t *testing.T) {
	for _, kind := range l2Kinds {
		for _, c := range []struct {
			class    string
			prefixes []string
		}{
			{"demox.HotService", []string{"demo."}},
			{"Demo.HotService", []string{"demo."}},
			{"demo", []string{"demo."}},
			{"HotService", []string{"demo."}},
			{"org.demo.HotService", []string{"demo."}},
			{"demo.HotService", nil},
			{"demo.HotService", []string{}},
			{"demo.HotService", []string{"com.example."}},
		} {
			req := validL2(kind)
			req.Class = c.class
			if got, err := Build(req, Policy{ClassPrefixes: c.prefixes}); err == nil {
				t.Errorf("%s with prefixes %q accepted class %s as %q", kind, c.prefixes, c.class, got.Text)
			}
		}
	}
}

func TestBuildL2RejectsBadPrefixEntries(t *testing.T) {
	bad := append([]string{"demo", "demo..", ".demo.", "demo.*", "demo.a", "java.", "java.util.", "javax.", "sun.", "com.sun.", "jdk.internal.",
		"com.taobao.arthas.", "com.alibaba.arthas.core.", "de mo.", "demo.;", strings.Repeat("a.", 130)}, hostile...)
	for _, p := range bad {
		if p == "a." {
			continue // a package prefix like any other
		}
		if err := CheckClassPrefix(p); err == nil {
			t.Errorf("CheckClassPrefix(%q) accepted", p)
		}
		// A bad entry is a configuration error even when another entry matches.
		req := validL2(KindWatch)
		if got, err := Build(req, Policy{ClassPrefixes: []string{"demo.", p}}); err == nil {
			t.Errorf("prefix entry %q accepted, built %q", p, got.Text)
		}
	}
	for _, p := range []string{"demo.", "com.example.", "a.b.c.", "$x.", "com."} {
		if err := CheckClassPrefix(p); err != nil {
			t.Errorf("CheckClassPrefix(%q): %v", p, err)
		}
	}
}

func TestBuildL2RejectsNumbersOutOfRange(t *testing.T) {
	for _, kind := range enhancingKinds {
		for _, n := range []int{-1, 0, 6, 100, 1 << 30} {
			req := validL2(kind)
			req.Count = n
			if got, err := Build(req, l2Policy); err == nil {
				t.Errorf("%s accepted count %d as %q", kind, n, got.Text)
			}
		}
		for _, n := range []int64{-1, MaxMinCost + 1, 1 << 40, -9223372036854775808} {
			req := validL2(kind)
			req.MinCost = n
			if got, err := Build(req, l2Policy); err == nil {
				t.Errorf("%s accepted minimum cost %d as %q", kind, n, got.Text)
			}
		}
	}
	for _, n := range []int{-1, 0, 3, 10} {
		req := validL2(KindWatch)
		req.Expand = n
		if got, err := Build(req, l2Policy); err == nil {
			t.Errorf("watch accepted expand %d as %q", n, got.Text)
		}
	}
	// count × cycle must stay below the enhancement time.
	for _, c := range []struct {
		count, cycle int
		enhance      time.Duration
		ok           bool
	}{
		{1, 0, 30 * time.Second, false},
		{1, -1, 30 * time.Second, false},
		{1, 30, 30 * time.Second, false},
		{1, 31, 30 * time.Second, false},
		{5, 6, 30 * time.Second, false},
		{3, 10, 30 * time.Second, false},
		{5, 5, 30 * time.Second, true},
		{2, 14, 30 * time.Second, true},
		{2, 5, 10 * time.Second, false},
		{3, 3, 10 * time.Second, true},
		{1, 1, time.Second, false},
		{1, 1, 2 * time.Second, true},
	} {
		req := validL2(KindMonitor)
		req.Count, req.Cycle = c.count, c.cycle
		got, err := Build(req, Policy{ClassPrefixes: []string{"demo."}, Enhance: c.enhance})
		if (err == nil) != c.ok {
			t.Errorf("monitor -n %d -c %d with %s: %q, %v", c.count, c.cycle, c.enhance, got.Text, err)
		}
	}
}

func TestBuildL2RejectsBadPolicyLimits(t *testing.T) {
	for _, d := range []time.Duration{-time.Second, time.Millisecond, 500 * time.Millisecond, 1500 * time.Millisecond, 31 * time.Second, time.Hour} {
		for _, kind := range enhancingKinds {
			if got, err := Build(validL2(kind), Policy{ClassPrefixes: []string{"demo."}, Enhance: d}); err == nil {
				t.Errorf("%s accepted enhancement time %s as %q", kind, d, got.Text)
			}
		}
	}
	for _, n := range []int{-1, 6, 50} {
		if got, err := Build(validL2(KindTrace), Policy{ClassPrefixes: []string{"demo."}, MaxMethods: n}); err == nil {
			t.Errorf("max methods %d accepted as %q", n, got.Text)
		}
	}
	for _, n := range []int{-1, 1, 255, MaxObjectSizeLimit + 1, 10 << 20} {
		if got, err := Build(validL2(KindWatch), Policy{ClassPrefixes: []string{"demo."}, ObjectSizeLimit: n}); err == nil {
			t.Errorf("object size limit %d accepted as %q", n, got.Setup)
		}
	}
	for _, n := range []int{MinObjectSizeLimit, MaxObjectSizeLimit} {
		got, err := Build(validL2(KindWatch), Policy{ClassPrefixes: []string{"demo."}, ObjectSizeLimit: n})
		if err != nil || !slices.Contains(got.Setup, "options object-size-limit "+strconv.Itoa(n)) {
			t.Errorf("object size limit %d: %q, %v", n, got.Setup, err)
		}
	}
}

func TestBuildWatchExpressions(t *testing.T) {
	for _, e := range WatchExpressions() {
		req := validL2(KindWatch)
		req.Express = e
		got, err := Build(req, l2Policy)
		if err != nil || !strings.Contains(got.Text, " {"+e+"} ") {
			t.Errorf("express %q: %q, %v", e, got.Text, err)
		}
	}
	if len(WatchExpressions()) != 7 {
		t.Errorf("WatchExpressions() = %q", WatchExpressions())
	}
	bad := append([]string{"target", "params,target", "params,params", "returnObj,params", "throwExp,params", "{params}", "params returnObj",
		"params, returnObj", "params,", ",params", "params,returnObj,throwExp,target", "#cost", "params.length", "params[0]",
		"@java.lang.Runtime@getRuntime().exec('id')", "params,@java.lang.System@exit(1)", "returnObj.toString()", "PARAMS", "clazz", "method"}, hostile...)
	for _, e := range bad {
		req := validL2(KindWatch)
		req.Express = e
		if got, err := Build(req, l2Policy); err == nil {
			t.Errorf("express %q accepted as %q", e, got.Text)
		}
	}
}

func TestBuildL2RejectsFieldsOfOtherKinds(t *testing.T) {
	cases := []Request{}
	add := func(kind Kind, change func(*Request)) {
		req := validL2(kind)
		change(&req)
		cases = append(cases, req)
	}
	add(KindTrace, func(r *Request) { r.Express = "params" })
	add(KindTrace, func(r *Request) { r.Expand = 1 })
	add(KindTrace, func(r *Request) { r.Cycle = 1 })
	add(KindStack, func(r *Request) { r.Express = "params" })
	add(KindStack, func(r *Request) { r.Cycle = 1 })
	add(KindMonitor, func(r *Request) { r.Expand = 1 })
	add(KindWatch, func(r *Request) { r.Cycle = 1 })
	add(KindWatch, func(r *Request) { r.Top = 1 })
	add(KindWatch, func(r *Request) { r.Key = "java.version" })
	add(KindWatch, func(r *Request) { r.ThreadID = 1 })
	add(KindJad, func(r *Request) { r.Count = 1 })
	add(KindJad, func(r *Request) { r.MinCost = 1 })
	add(KindJad, func(r *Request) { r.Express = "params" })
	add(KindJad, func(r *Request) { r.Cycle = 1 })
	for _, req := range cases {
		if got, err := Build(req, l2Policy); err == nil {
			t.Errorf("%+v accepted as %q", req, got.Text)
		}
	}
}

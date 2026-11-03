package jvmarthas

import (
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/arthas"
	"github.com/liubing0806/allowops/internal/jvmtarget"
)

const sumA = "b5bf8765c7621849889fb6522a296fa177ceb3f5c2c2b6d9f631d761ca9c04f9"

func goodSHA() map[string]string {
	m := map[string]string{}
	for _, name := range FileNames {
		m[name] = sumA
	}
	return m
}

func goodConfig() Config {
	return Config{
		Command: arthas.KindDashboard,
		Targets: map[string]jvmtarget.Target{
			"api":  {Name: "api", SystemdUnit: "api.service"},
			"shop": {Name: "shop", Container: "shop-web", MainClass: "com.example.Main"},
		},
		SHA256: goodSHA(),
	}
}

func TestValidateAcceptsEveryCommandKind(t *testing.T) {
	for _, kind := range arthas.Kinds() {
		cfg := goodConfig()
		cfg.Command = kind
		if kind == arthas.KindSysprop {
			cfg.SyspropKeys = []string{"java.version", "user.timezone"}
		}
		if kind.Level() == 2 {
			cfg.ClassPrefixes = []string{"com.example."}
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("%s: %v", kind, err)
		}
		if err := cfg.Effective().Validate(); err != nil {
			t.Errorf("%s: effective configuration: %v", kind, err)
		}
	}
}

func l2Config(kind arthas.Kind) Config {
	cfg := goodConfig()
	cfg.Command = kind
	cfg.ClassPrefixes = []string{"com.example.", "demo."}
	return cfg
}

func TestValidateL2Settings(t *testing.T) {
	tests := []struct {
		name   string
		kind   arthas.Kind
		change func(*Config)
		want   string
	}{
		{"L2 without class prefixes", arthas.KindWatch, func(c *Config) { c.ClassPrefixes = nil }, "class_prefixes must list"},
		{"jad without class prefixes", arthas.KindJad, func(c *Config) { c.ClassPrefixes = []string{} }, "class_prefixes must list"},
		{"too many class prefixes", arthas.KindTrace, func(c *Config) {
			c.ClassPrefixes = nil
			for i := 0; i <= MaxClassPrefixes; i++ {
				c.ClassPrefixes = append(c.ClassPrefixes, "p"+strings.Repeat("x", i)+".")
			}
		}, "class_prefixes must list"},
		{"prefix without a dot", arthas.KindWatch, func(c *Config) { c.ClassPrefixes = []string{"com.example"} }, "class_prefixes"},
		{"prefix with a wildcard", arthas.KindWatch, func(c *Config) { c.ClassPrefixes = []string{"com.*."} }, "class_prefixes"},
		{"forbidden prefix", arthas.KindStack, func(c *Config) { c.ClassPrefixes = []string{"com.example.", "java.util."} }, "class_prefixes"},
		{"Arthas prefix", arthas.KindJad, func(c *Config) { c.ClassPrefixes = []string{"com.taobao.arthas."} }, "class_prefixes"},
		{"class prefixes on an L1 command", arthas.KindClassInfo, func(c *Config) {}, "class_prefixes applies to the L2 commands only"},
		{"enhancement above 30s", arthas.KindWatch, func(c *Config) { c.EnhanceDuration = 31 * time.Second }, "enhance_duration"},
		{"enhancement below 1s", arthas.KindTrace, func(c *Config) { c.EnhanceDuration = 500 * time.Millisecond }, "enhance_duration"},
		{"enhancement in parts of a second", arthas.KindMonitor, func(c *Config) { c.EnhanceDuration = 1500 * time.Millisecond }, "enhance_duration"},
		{"negative enhancement", arthas.KindStack, func(c *Config) { c.EnhanceDuration = -time.Second }, "enhance_duration"},
		{"monitor with one second", arthas.KindMonitor, func(c *Config) { c.EnhanceDuration = time.Second }, "enhance_duration of monitor must be at least 2s"},
		{"enhancement for jad", arthas.KindJad, func(c *Config) { c.EnhanceDuration = 10 * time.Second }, "enhance_duration applies to"},
		{"more methods than the default", arthas.KindWatch, func(c *Config) { c.MaxMethods = 6 }, "max_methods"},
		{"negative methods", arthas.KindWatch, func(c *Config) { c.MaxMethods = -1 }, "max_methods"},
		{"methods for jad", arthas.KindJad, func(c *Config) { c.MaxMethods = 1 }, "max_methods applies to"},
		{"object size above 64 KiB", arthas.KindWatch, func(c *Config) { c.ObjectSizeLimit = 64<<10 + 1 }, "object_size_limit"},
		{"object size below 256 bytes", arthas.KindWatch, func(c *Config) { c.ObjectSizeLimit = 255 }, "object_size_limit"},
		{"object size for trace", arthas.KindTrace, func(c *Config) { c.ObjectSizeLimit = 1024 }, "object_size_limit applies to watch only"},
		{"cpu share above the default", arthas.KindWatch, func(c *Config) { c.Checks.MaxCPUPercent = 51 }, "max_cpu_percent"},
		{"negative cpu share", arthas.KindJad, func(c *Config) { c.Checks.MaxCPUPercent = -1 }, "max_cpu_percent"},
		{"cpu share on an L1 command", arthas.KindDashboard, func(c *Config) { c.ClassPrefixes = nil; c.Checks.MaxCPUPercent = 10 }, "max_cpu_percent applies to the L2 commands only"},
		{"enhancement on an L1 command", arthas.KindVersion, func(c *Config) { c.ClassPrefixes = nil; c.EnhanceDuration = time.Second }, "enhance_duration applies to"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := l2Config(tc.kind)
			tc.change(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v; want an error mentioning %q", err, tc.want)
			}
		})
	}
	cfg := l2Config(arthas.KindWatch)
	cfg.EnhanceDuration, cfg.MaxMethods, cfg.ObjectSizeLimit, cfg.Checks.MaxCPUPercent = time.Second, 1, 64<<10, 1
	if err := cfg.Validate(); err != nil {
		t.Errorf("tighter watch settings: %v", err)
	}
}

func TestEffectiveFillsTheL2Defaults(t *testing.T) {
	watch := l2Config(arthas.KindWatch).Effective()
	if watch.EnhanceDuration != 30*time.Second || watch.MaxMethods != 5 || watch.ObjectSizeLimit != 8<<10 || watch.Checks.MaxCPUPercent != 50 {
		t.Errorf("watch: %+v", watch)
	}
	trace := l2Config(arthas.KindTrace).Effective()
	if trace.EnhanceDuration != 30*time.Second || trace.MaxMethods != 5 || trace.ObjectSizeLimit != 0 || trace.Checks.MaxCPUPercent != 50 {
		t.Errorf("trace: %+v", trace)
	}
	jad := l2Config(arthas.KindJad).Effective()
	if jad.EnhanceDuration != 0 || jad.MaxMethods != 0 || jad.ObjectSizeLimit != 0 || jad.Checks.MaxCPUPercent != 50 {
		t.Errorf("jad: %+v", jad)
	}
	l1 := goodConfig().Effective()
	if l1.EnhanceDuration != 0 || l1.MaxMethods != 0 || l1.ObjectSizeLimit != 0 || l1.Checks.MaxCPUPercent != 0 {
		t.Errorf("dashboard: %+v", l1)
	}
}

func TestValidateRejects(t *testing.T) {
	longKeys := make([]string, 65)
	for i := range longKeys {
		longKeys[i] = "key.n" + strings.Repeat("a", i%5) + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	tests := []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"unknown command", func(c *Config) { c.Command = "ognl" }, "command"},
		{"paused logger command", func(c *Config) { c.Command = arthas.KindLogger }, "logger is paused: after logger the class loader of Arthas is not unloaded"},
		{"no command", func(c *Config) { c.Command = "" }, "command"},
		{"no targets", func(c *Config) { c.Targets = nil }, "target"},
		{"too many targets", func(c *Config) {
			c.Targets = map[string]jvmtarget.Target{}
			for i := 0; i <= MaxTargets; i++ {
				name := "t" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + string(rune('a'+i/26))
				c.Targets[name] = jvmtarget.Target{Name: name, SystemdUnit: "a.service"}
			}
		}, "at most"},
		{"target name differs from its key", func(c *Config) { c.Targets["api"] = jvmtarget.Target{Name: "other", SystemdUnit: "api.service"} }, "differs"},
		{"invalid target", func(c *Config) { c.Targets["api"] = jvmtarget.Target{Name: "api"} }, "target api"},
		{"missing checksum", func(c *Config) { delete(c.SHA256, "logback.xml") }, "logback.xml"},
		{"unknown checksum entry", func(c *Config) { c.SHA256["arthas-boot.jar"] = sumA }, "arthas-boot.jar"},
		{"short checksum", func(c *Config) { c.SHA256["arthas-core.jar"] = sumA[:63] }, "arthas-core.jar"},
		{"upper-case checksum", func(c *Config) { c.SHA256["arthas-core.jar"] = strings.ToUpper(sumA) }, "arthas-core.jar"},
		{"relative directory", func(c *Config) { c.ArthasDir = "arthas/4.3.5" }, "arthas_dir"},
		{"directory with dot dot", func(c *Config) { c.ArthasDir = "/opt/arthas/../x" }, "arthas_dir"},
		{"directory with semicolon", func(c *Config) { c.ArthasDir = "/opt/a;b" }, "arthas_dir"},
		{"directory with percent", func(c *Config) { c.ArthasDir = "/opt/a%2eb" }, "arthas_dir"},
		{"directory with equals sign", func(c *Config) { c.ArthasDir = "/opt/a=b" }, "arthas_dir"},
		{"directory with trailing slash", func(c *Config) { c.ArthasDir = "/opt/arthas/" }, "arthas_dir"},
		{"port range below 1024", func(c *Config) { c.HTTPPortMin, c.HTTPPortMax = 80, 90 }, "port"},
		{"port range reversed", func(c *Config) { c.HTTPPortMin, c.HTTPPortMax = 20000, 19000 }, "port"},
		{"port range above 65535", func(c *Config) { c.HTTPPortMin, c.HTTPPortMax = 65000, 65536 }, "port"},
		{"only one port bound", func(c *Config) { c.HTTPPortMin = 20000 }, "port"},
		{"exec timeout above 60s", func(c *Config) { c.ExecTimeout = 61 * time.Second }, "exec_timeout"},
		{"negative exec timeout", func(c *Config) { c.ExecTimeout = -time.Second }, "exec_timeout"},
		{"sysprop without keys", func(c *Config) { c.Command = arthas.KindSysprop }, "sysprop_keys"},
		{"sysprop key with a space", func(c *Config) { c.Command = arthas.KindSysprop; c.SyspropKeys = []string{"a b"} }, "sysprop"},
		{"sysprop key list too long", func(c *Config) { c.Command = arthas.KindSysprop; c.SyspropKeys = longKeys }, "sysprop_keys"},
		{"keys on another command", func(c *Config) { c.SyspropKeys = []string{"java.version"} }, "sysprop_keys"},

		{"memory headroom below the default", func(c *Config) { c.Checks.MinMemoryHeadroom = 255 << 20 }, "min_memory_headroom"},
		{"metaspace headroom below the default", func(c *Config) { c.Checks.MinMetaspaceHeadroom = 63 << 20 }, "min_metaspace_headroom"},
		{"more attaches than the default", func(c *Config) { c.Checks.MaxAttaches = 6 }, "max_attaches"},
		{"negative attaches", func(c *Config) { c.Checks.MaxAttaches = -1 }, "max_attaches"},
		{"attach interval below the default", func(c *Config) { c.Checks.MinAttachInterval = 59 * time.Second }, "min_attach_interval"},
		{"negative attach interval", func(c *Config) { c.Checks.MinAttachInterval = -time.Second }, "min_attach_interval"},
		{"more blocking threads than the default", func(c *Config) { c.Checks.MaxBlockingThreads = 1001 }, "max_blocking_threads"},
		{"negative blocking threads", func(c *Config) { c.Checks.MaxBlockingThreads = -1 }, "max_blocking_threads"},
		{"old generation above the default", func(c *Config) { c.Checks.MaxOldGenPercent = 86 }, "max_old_gen_percent"},
		{"old generation above 100 percent", func(c *Config) { c.Checks.MaxOldGenPercent = 101 }, "max_old_gen_percent"},
		{"negative old generation", func(c *Config) { c.Checks.MaxOldGenPercent = -1 }, "max_old_gen_percent"},
		{"full gc window below the default", func(c *Config) { c.Checks.NoFullGCWithin = 59 * time.Second }, "no_full_gc_within"},
		{"full gc window above a day", func(c *Config) { c.Checks.NoFullGCWithin = 24*time.Hour + time.Second }, "no_full_gc_within"},
		{"negative full gc window", func(c *Config) { c.Checks.NoFullGCWithin = -time.Second }, "no_full_gc_within"},

		{"negative cpu", func(c *Config) { c.Guard.MaxCPUPercent = -1 }, "max_cpu_percent"},
		{"gc time above 100 percent", func(c *Config) { c.Guard.MaxGCTimePercent = 101 }, "max_gc_time_percent"},
		{"negative gc rate", func(c *Config) { c.Guard.MaxGCPerSecond = -1 }, "max_gc_per_second"},
		{"negative settle time", func(c *Config) { c.Guard.Settle = -time.Second }, "settle"},
		{"settle time above a minute", func(c *Config) { c.Guard.Settle = 61 * time.Second }, "settle"},
		{"health check without prefixes", func(c *Config) { c.Guard.Health = &HealthCheck{URL: "http://127.0.0.1:8080/health"} }, "health_check"},
		{"health check outside its prefixes", func(c *Config) {
			c.Guard.Health = &HealthCheck{URL: "http://127.0.0.1:9090/health", AllowedPrefixes: []string{"http://127.0.0.1:8080/"}}
		}, "health_check"},
		{"health check with credentials", func(c *Config) {
			c.Guard.Health = &HealthCheck{URL: "http://user:pw@127.0.0.1:8080/health", AllowedPrefixes: []string{"http://127.0.0.1:8080/"}}
		}, "health_check"},
		{"health check timeout above 10s", func(c *Config) {
			c.Guard.Health = &HealthCheck{URL: "http://127.0.0.1:8080/health", AllowedPrefixes: []string{"http://127.0.0.1:8080/"}, Timeout: 11 * time.Second}
		}, "health_check"},
		{"health check failure count above 10", func(c *Config) {
			c.Guard.Health = &HealthCheck{URL: "http://127.0.0.1:8080/health", AllowedPrefixes: []string{"http://127.0.0.1:8080/"}, MaxFailures: 11}
		}, "health_check"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := goodConfig()
			tc.change(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("accepted; want an error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestValidateAcceptsTighterThresholds(t *testing.T) {
	cfg := goodConfig()
	cfg.ArthasDir = "/opt/arthas-minlog"
	cfg.HTTPPortMin, cfg.HTTPPortMax = 20000, 20000
	cfg.ExecTimeout = 60 * time.Second
	cfg.Checks = Checks{
		MinMemoryHeadroom: 512 << 20, MinMetaspaceHeadroom: 64 << 20, MaxAttaches: 3,
		MinAttachInterval: 5 * time.Minute, MaxBlockingThreads: 100, MaxOldGenPercent: 1, NoFullGCWithin: 24 * time.Hour,
	}
	cfg.Guard = Guard{
		MaxCPUPercent: 300, MaxGCTimePercent: 50, MaxGCPerSecond: 5, Settle: 5 * time.Second,
		Health: &HealthCheck{URL: "http://127.0.0.1:8080/health", AllowedPrefixes: []string{"http://127.0.0.1:8080/"}, Timeout: 10 * time.Second, MaxFailures: 10, MaxLatency: time.Second},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestEffectiveFillsTheDefaults(t *testing.T) {
	got := goodConfig().Effective()
	want := Checks{
		MinMemoryHeadroom: 256 << 20, MinMetaspaceHeadroom: 64 << 20, MaxAttaches: 5,
		MinAttachInterval: 60 * time.Second, MaxBlockingThreads: 1000, MaxOldGenPercent: 85, NoFullGCWithin: 60 * time.Second,
	}
	if got.Checks != want {
		t.Errorf("checks = %+v, want %+v", got.Checks, want)
	}
	if got.ArthasDir != "/usr/share/allowops/arthas/4.3.5" {
		t.Errorf("arthas dir = %q", got.ArthasDir)
	}
	if got.HTTPPortMin != DefaultHTTPPortMin || got.HTTPPortMax != DefaultHTTPPortMax {
		t.Errorf("ports = %d-%d", got.HTTPPortMin, got.HTTPPortMax)
	}
	if got.ExecTimeout != 10*time.Second {
		t.Errorf("exec timeout = %s", got.ExecTimeout)
	}
	if got.Guard.MaxCPUPercent != 0 || got.Guard.MaxGCTimePercent != 0 || got.Guard.MaxGCPerSecond != 0 || got.Guard.Health != nil {
		t.Errorf("guard = %+v, want every check off", got.Guard)
	}
}

func TestEffectiveKeepsTighterValuesAndHealthCheckDefaults(t *testing.T) {
	cfg := goodConfig()
	cfg.Checks.MinMemoryHeadroom = 1 << 30
	cfg.Checks.MaxAttaches = 2
	cfg.Guard.Health = &HealthCheck{URL: "http://127.0.0.1:8080/health", AllowedPrefixes: []string{"http://127.0.0.1:8080/"}}
	got := cfg.Effective()
	if got.Checks.MinMemoryHeadroom != 1<<30 || got.Checks.MaxAttaches != 2 {
		t.Errorf("checks = %+v", got.Checks)
	}
	if got.Guard.Health.Timeout != 2*time.Second || got.Guard.Health.MaxFailures != 2 {
		t.Errorf("health check = %+v", got.Guard.Health)
	}
	if cfg.Guard.Health.Timeout != 0 {
		t.Error("Effective changed the receiver's health check")
	}
}

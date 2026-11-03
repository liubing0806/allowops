package jvmarthas

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/liubing0806/allowops/internal/arthas"
	"github.com/liubing0806/allowops/internal/builtin/httpget"
	"github.com/liubing0806/allowops/internal/jvmtarget"
)

// MaxTargets bounds the allowlist of one action.
const MaxTargets = 64

// DefaultDir is where the allowops-arthas package puts the Arthas files.
const DefaultDir = "/usr/share/allowops/arthas/" + arthas.Version

// FileNames are the five files a call needs, in the order they are checked.
var FileNames = []string{"arthas-agent.jar", "arthas-core.jar", "arthas-spy.jar", "arthas.properties", "logback.xml"}

// Limits that builtin_config can tighten but not loosen (decision A67), and the
// values used when the field is not set.
const (
	DefaultMinMemoryHeadroom    int64 = 256 << 20
	DefaultMinMetaspaceHeadroom int64 = 64 << 20
	// DefaultMaxAttaches is the number of attaches a JVM may have had during its life
	// before a new one is refused.
	DefaultMaxAttaches       = 5
	DefaultMinAttachInterval = 60 * time.Second
	// DefaultMaxBlockingThreads is the largest java.threads.live for thread -b (decision A69).
	DefaultMaxBlockingThreads = 1000
	// DefaultMaxOldGenPercent and DefaultNoFullGCWithin are the old generation checks (decision A69).
	DefaultMaxOldGenPercent = 85
	DefaultNoFullGCWithin   = 60 * time.Second

	// DefaultMaxCPUPercent is the CPU use of the JVM, in percent of its CPU limit, from which an
	// L2 command is refused.
	DefaultMaxCPUPercent = 50

	DefaultExecTimeout = 10 * time.Second
	DefaultHTTPPortMin = 18563
	DefaultHTTPPortMax = 18662
)

// Config is trusted catalog configuration. Zero values select the defaults
// above, or switch an optional check off; Validate rejects values that are
// looser than a default.
type Config struct {
	// Command is the one command kind this action runs.
	Command arthas.Kind
	// Targets maps the name a caller selects to the unit or container.
	Targets map[string]jvmtarget.Target
	// ArthasDir holds the Arthas files, in the file system of the target. DefaultDir when empty.
	ArthasDir string
	// SHA256 maps each of FileNames to its lower-case hex SHA-256.
	SHA256 map[string]string
	// HTTPPortMin and HTTPPortMax bound the port Arthas listens on, inside the
	// target's network namespace. Both zero selects the default range.
	HTTPPortMin, HTTPPortMax int
	ExecTimeout              time.Duration
	// SyspropKeys are the properties the sysprop command may read.
	SyspropKeys []string
	// ClassPrefixes are the package prefixes, each ending with a dot, that the class of an L2
	// command must start with. Required for the L2 commands and not allowed for the others.
	ClassPrefixes []string
	// EnhanceDuration is how long the enhancement of watch, trace, stack and monitor lasts, in
	// whole seconds; arthas.DefaultEnhance when zero, and it can only be shortened.
	EnhanceDuration time.Duration
	// MaxMethods is the most methods one enhancement may affect; arthas.DefaultMaxMethods when
	// zero, and it can only be lowered.
	MaxMethods int
	// ObjectSizeLimit bounds one watch value, in bytes; arthas.DefaultObjectSizeLimit when zero.
	ObjectSizeLimit int
	Checks          Checks
	Guard           Guard
}

// Checks are the thresholds of the checks before the attach.
type Checks struct {
	// MinMemoryHeadroom is the memory limit of the target's cgroup minus its usage, in bytes.
	MinMemoryHeadroom int64
	// MinMetaspaceHeadroom is MaxMetaspaceSize minus the metaspace in use, in bytes.
	// The check is skipped when the JVM has no MaxMetaspaceSize.
	MinMetaspaceHeadroom int64
	// MaxAttaches refuses the call when the JVM had this many attaches already.
	MaxAttaches int
	// MinAttachInterval is the time since the last attach to this JVM.
	MinAttachInterval time.Duration
	// MaxBlockingThreads is the largest java.threads.live for the thread_blocking command.
	MaxBlockingThreads int
	// MaxOldGenPercent refuses the call when the old generation is fuller than this
	// percentage of its limit.
	MaxOldGenPercent int
	// NoFullGCWithin refuses the call when a full collection ended within this time.
	NoFullGCWithin time.Duration
	// MaxCPUPercent refuses an L2 command when the JVM used this share of its CPU limit or more,
	// measured over a few seconds before the attach.
	MaxCPUPercent int
}

// Guard are the thresholds watched while the session is open. A zero value
// switches the check off.
type Guard struct {
	// MaxCPUPercent is the CPU time of the JVM in one second, in percent of one
	// CPU: 100 is one fully used CPU, 400 four.
	MaxCPUPercent int
	// MaxGCTimePercent is the share of a second spent in garbage collection.
	MaxGCTimePercent int
	// MaxGCPerSecond is the number of collections in one second.
	MaxGCPerSecond int
	// Settle is the time after the attach in which no threshold is evaluated.
	Settle time.Duration
	Health *HealthCheck
}

// HealthCheck is a GET request sent every second. Its address is bound by the
// same rules as the http_get builtin.
type HealthCheck struct {
	URL             string
	AllowedPrefixes []string
	// Timeout is 2 seconds when zero.
	Timeout time.Duration
	// MaxFailures is the number of failed requests in a row that aborts the call; 2 when zero.
	MaxFailures int
	// MaxLatency counts a slower answer as failed. Zero switches it off.
	MaxLatency time.Duration
}

// Validate checks the configuration.
func (c Config) Validate() error {
	if reason, paused := arthas.Paused(c.Command); paused {
		return fmt.Errorf("jvm_arthas command %s is paused: %s", c.Command, reason)
	}
	if !slices.Contains(arthas.Kinds(), c.Command) {
		return fmt.Errorf("jvm_arthas command %q is not one of: %s", c.Command, kindList())
	}
	if len(c.Targets) == 0 {
		return errors.New("jvm_arthas requires at least one target")
	}
	if len(c.Targets) > MaxTargets {
		return fmt.Errorf("jvm_arthas allows at most %d targets", MaxTargets)
	}
	for _, name := range c.TargetNames() {
		t := c.Targets[name]
		if t.Name != name {
			return fmt.Errorf("target %q: name field %q differs", name, t.Name)
		}
		if err := t.Validate(); err != nil {
			return fmt.Errorf("target %q: %w", name, err)
		}
	}
	if err := c.validateFiles(); err != nil {
		return err
	}
	if err := c.validateLimits(); err != nil {
		return err
	}
	if err := c.validateSysprop(); err != nil {
		return err
	}
	if err := c.validateL2(); err != nil {
		return err
	}
	if err := c.Checks.validate(); err != nil {
		return err
	}
	return c.Guard.validate()
}

func kindList() string {
	kinds := arthas.Kinds()
	names := make([]string, len(kinds))
	for i, k := range kinds {
		names[i] = string(k)
	}
	return strings.Join(names, ", ")
}

// TargetNames returns the selectable names in order.
func (c Config) TargetNames() []string {
	names := make([]string, 0, len(c.Targets))
	for name := range c.Targets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

var (
	// dirPattern keeps out every byte that Arthas reads differently from what is written
	// in its agent argument (arthas.AgentConfig checks the same set again).
	dirPattern    = regexp.MustCompile(`^/[A-Za-z0-9_./-]*$`)
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

const maxDirLen = 200

func (c Config) validateFiles() error {
	if dir := c.ArthasDir; dir != "" {
		if len(dir) > maxDirLen || !dirPattern.MatchString(dir) || path.Clean(dir) != dir {
			return fmt.Errorf("arthas_dir must be a clean absolute path of letters, digits and _ . / - (at most %d bytes)", maxDirLen)
		}
	}
	for _, name := range FileNames {
		sum, ok := c.SHA256[name]
		if !ok {
			return fmt.Errorf("arthas_sha256 needs an entry for %s", name)
		}
		if !sha256Pattern.MatchString(sum) {
			return fmt.Errorf("arthas_sha256 for %s must be 64 lower-case hex digits", name)
		}
	}
	for name := range c.SHA256 {
		if !slices.Contains(FileNames, name) {
			return fmt.Errorf("arthas_sha256 has an entry for %s; allowed: %s", name, strings.Join(FileNames, ", "))
		}
	}
	return nil
}

func (c Config) validateLimits() error {
	switch lo, hi := c.HTTPPortMin, c.HTTPPortMax; {
	case lo == 0 && hi == 0:
	case lo < 1024 || hi > 65535 || lo > hi:
		return fmt.Errorf("http_port_min and http_port_max must be set together and satisfy 1024 <= min <= max <= 65535, got %d and %d", lo, hi)
	}
	if c.ExecTimeout < 0 || c.ExecTimeout > arthas.MaxExecTimeout {
		return fmt.Errorf("exec_timeout must be between 0s and %s", arthas.MaxExecTimeout)
	}
	return nil
}

const maxSyspropKeys = 64

func (c Config) validateSysprop() error {
	if c.Command != arthas.KindSysprop {
		if len(c.SyspropKeys) > 0 {
			return fmt.Errorf("sysprop_keys applies to the sysprop command only, not to %s", c.Command)
		}
		return nil
	}
	if len(c.SyspropKeys) == 0 || len(c.SyspropKeys) > maxSyspropKeys {
		return fmt.Errorf("sysprop_keys must list 1 to %d system property keys", maxSyspropKeys)
	}
	policy := arthas.Policy{SyspropKeys: c.SyspropKeys}
	for _, key := range c.SyspropKeys {
		if _, err := arthas.Build(arthas.Request{Kind: arthas.KindSysprop, Key: key}, policy); err != nil {
			return fmt.Errorf("sysprop_keys: %w", err)
		}
	}
	return nil
}

// MaxClassPrefixes bounds class_prefixes.
const MaxClassPrefixes = 32

// validateL2 checks the settings of the L2 commands, and that none of them is set for a
// command it does not apply to.
func (c Config) validateL2() error {
	kind := c.Command
	l2, enhances := kind.Level() == 2, kind.Enhances()
	switch {
	case !l2 && len(c.ClassPrefixes) > 0:
		return fmt.Errorf("class_prefixes applies to the L2 commands only, not to %s", kind)
	case !l2 && c.Checks.MaxCPUPercent != 0:
		return fmt.Errorf("checks.max_cpu_percent applies to the L2 commands only, not to %s", kind)
	case !enhances && c.EnhanceDuration != 0:
		return fmt.Errorf("enhance_duration applies to watch, trace, stack and monitor only, not to %s", kind)
	case !enhances && c.MaxMethods != 0:
		return fmt.Errorf("max_methods applies to watch, trace, stack and monitor only, not to %s", kind)
	case kind != arthas.KindWatch && c.ObjectSizeLimit != 0:
		return fmt.Errorf("object_size_limit applies to watch only, not to %s", kind)
	}
	if !l2 {
		return nil
	}
	if len(c.ClassPrefixes) == 0 || len(c.ClassPrefixes) > MaxClassPrefixes {
		return fmt.Errorf("class_prefixes must list 1 to %d package prefixes for %s", MaxClassPrefixes, kind)
	}
	for _, prefix := range c.ClassPrefixes {
		if err := arthas.CheckClassPrefix(prefix); err != nil {
			return fmt.Errorf("class_prefixes: %w", err)
		}
	}
	switch d := c.EnhanceDuration; {
	case d != 0 && (d < time.Second || d > arthas.MaxEnhance || d%time.Second != 0):
		return fmt.Errorf("enhance_duration may only be shortened, to whole seconds between 1s and %s", arthas.MaxEnhance)
	case kind == arthas.KindMonitor && d == time.Second:
		return errors.New("enhance_duration of monitor must be at least 2s: one period of at least 1s has to end before the enhancement")
	case c.MaxMethods != 0 && (c.MaxMethods < 1 || c.MaxMethods > arthas.DefaultMaxMethods):
		return fmt.Errorf("max_methods may only be lowered, to between 1 and %d", arthas.DefaultMaxMethods)
	case c.ObjectSizeLimit != 0 && (c.ObjectSizeLimit < arthas.MinObjectSizeLimit || c.ObjectSizeLimit > arthas.MaxObjectSizeLimit):
		return fmt.Errorf("object_size_limit must be between %d and %d bytes", arthas.MinObjectSizeLimit, arthas.MaxObjectSizeLimit)
	}
	return nil
}

func (k Checks) validate() error {
	switch {
	case k.MinMemoryHeadroom != 0 && k.MinMemoryHeadroom < DefaultMinMemoryHeadroom:
		return fmt.Errorf("checks.min_memory_headroom may only be raised above %d bytes", DefaultMinMemoryHeadroom)
	case k.MinMetaspaceHeadroom != 0 && k.MinMetaspaceHeadroom < DefaultMinMetaspaceHeadroom:
		return fmt.Errorf("checks.min_metaspace_headroom may only be raised above %d bytes", DefaultMinMetaspaceHeadroom)
	case k.MaxAttaches != 0 && (k.MaxAttaches < 1 || k.MaxAttaches > DefaultMaxAttaches):
		return fmt.Errorf("checks.max_attaches may only be lowered, to between 1 and %d", DefaultMaxAttaches)
	case k.MinAttachInterval != 0 && (k.MinAttachInterval < DefaultMinAttachInterval || k.MinAttachInterval > 24*time.Hour):
		return fmt.Errorf("checks.min_attach_interval may only be raised above %s (at most 24h)", DefaultMinAttachInterval)
	case k.MaxBlockingThreads != 0 && (k.MaxBlockingThreads < 1 || k.MaxBlockingThreads > DefaultMaxBlockingThreads):
		return fmt.Errorf("checks.max_blocking_threads may only be lowered, to between 1 and %d", DefaultMaxBlockingThreads)
	case k.MaxOldGenPercent != 0 && (k.MaxOldGenPercent < 1 || k.MaxOldGenPercent > DefaultMaxOldGenPercent):
		return fmt.Errorf("checks.max_old_gen_percent may only be lowered, to between 1 and %d", DefaultMaxOldGenPercent)
	case k.NoFullGCWithin != 0 && (k.NoFullGCWithin < DefaultNoFullGCWithin || k.NoFullGCWithin > 24*time.Hour):
		return fmt.Errorf("checks.no_full_gc_within may only be raised above %s (at most 24h)", DefaultNoFullGCWithin)
	case k.MaxCPUPercent != 0 && (k.MaxCPUPercent < 1 || k.MaxCPUPercent > DefaultMaxCPUPercent):
		return fmt.Errorf("checks.max_cpu_percent may only be lowered, to between 1 and %d", DefaultMaxCPUPercent)
	}
	return nil
}

const maxSettle = time.Minute

func (g Guard) validate() error {
	switch {
	case g.MaxCPUPercent < 0 || g.MaxCPUPercent > 100*1024:
		return errors.New("guard.max_cpu_percent must be between 0 and 102400")
	case g.MaxGCTimePercent < 0 || g.MaxGCTimePercent > 100:
		return errors.New("guard.max_gc_time_percent must be between 0 and 100")
	case g.MaxGCPerSecond < 0:
		return errors.New("guard.max_gc_per_second must not be negative")
	case g.Settle < 0 || g.Settle > maxSettle:
		return fmt.Errorf("guard.settle must be between 0s and %s", maxSettle)
	}
	if g.Health != nil {
		if err := g.Health.validate(); err != nil {
			return fmt.Errorf("guard.health_check: %w", err)
		}
	}
	return nil
}

func (h HealthCheck) validate() error {
	probe := httpget.Config{AllowedPrefixes: h.AllowedPrefixes}
	if err := probe.Validate(); err != nil {
		return err
	}
	if err := httpget.ValidateURL(h.URL, h.AllowedPrefixes); err != nil {
		return fmt.Errorf("url: %w", err)
	}
	switch {
	case h.Timeout < 0 || h.Timeout > 10*time.Second:
		return errors.New("timeout must be between 0s and 10s")
	case h.MaxFailures < 0 || h.MaxFailures > 10:
		return errors.New("max_failures must be between 0 and 10")
	case h.MaxLatency < 0 || h.MaxLatency > 10*time.Second:
		return errors.New("max_latency must be between 0s and 10s")
	}
	return nil
}

// Effective returns the configuration with the defaults filled in. The guard
// thresholds have no default and stay zero, which keeps their checks off.
func (c Config) Effective() Config {
	if c.ArthasDir == "" {
		c.ArthasDir = DefaultDir
	}
	if c.HTTPPortMin == 0 && c.HTTPPortMax == 0 {
		c.HTTPPortMin, c.HTTPPortMax = DefaultHTTPPortMin, DefaultHTTPPortMax
	}
	if c.ExecTimeout == 0 {
		c.ExecTimeout = DefaultExecTimeout
	}
	k := &c.Checks
	if k.MinMemoryHeadroom == 0 {
		k.MinMemoryHeadroom = DefaultMinMemoryHeadroom
	}
	if k.MinMetaspaceHeadroom == 0 {
		k.MinMetaspaceHeadroom = DefaultMinMetaspaceHeadroom
	}
	if k.MaxAttaches == 0 {
		k.MaxAttaches = DefaultMaxAttaches
	}
	if k.MinAttachInterval == 0 {
		k.MinAttachInterval = DefaultMinAttachInterval
	}
	if k.MaxBlockingThreads == 0 {
		k.MaxBlockingThreads = DefaultMaxBlockingThreads
	}
	if k.MaxOldGenPercent == 0 {
		k.MaxOldGenPercent = DefaultMaxOldGenPercent
	}
	if k.NoFullGCWithin == 0 {
		k.NoFullGCWithin = DefaultNoFullGCWithin
	}
	// The L2 settings get their defaults only where they apply, so that the result still
	// passes Validate.
	if c.Command.Level() == 2 && k.MaxCPUPercent == 0 {
		k.MaxCPUPercent = DefaultMaxCPUPercent
	}
	if c.Command.Enhances() {
		if c.EnhanceDuration == 0 {
			c.EnhanceDuration = arthas.DefaultEnhance
		}
		if c.MaxMethods == 0 {
			c.MaxMethods = arthas.DefaultMaxMethods
		}
	}
	if c.Command == arthas.KindWatch && c.ObjectSizeLimit == 0 {
		c.ObjectSizeLimit = arthas.DefaultObjectSizeLimit
	}
	if c.Guard.Health != nil {
		h := *c.Guard.Health
		if h.Timeout == 0 {
			h.Timeout = 2 * time.Second
		}
		if h.MaxFailures == 0 {
			h.MaxFailures = 2
		}
		c.Guard.Health = &h
	}
	return c
}

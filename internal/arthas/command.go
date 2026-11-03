package arthas

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Kind names one of the fixed commands. Level L1 commands only read: the JVM is attached but no
// class is changed. Level L2 commands enhance one method of one class for a bounded time (watch,
// trace, stack, monitor) or retransform a class to read its bytecode (jad).
type Kind string

const (
	KindDashboard       Kind = "dashboard"        // dashboard -n 1
	KindThreadTop       Kind = "thread_top"       // thread -n <1-10>
	KindThreadBlocking  Kind = "thread_blocking"  // thread -b
	KindThreadInfo      Kind = "thread_info"      // thread <id>
	KindMemory          Kind = "memory"           // memory
	KindJVM             Kind = "jvm"              // jvm
	KindClassInfo       Kind = "class_info"       // sc -d <class>
	KindMethodInfo      Kind = "method_info"      // sm -d <class> [method]
	KindClassLoaderTree Kind = "classloader_tree" // classloader -t
	KindClassLoaderList Kind = "classloader_list" // classloader -l
	KindLogger          Kind = "logger"           // logger; paused, see Paused
	KindSysprop         Kind = "sysprop"          // sysprop <allowed key>
	KindVersion         Kind = "version"          // version

	KindWatch   Kind = "watch"   // watch <class> <method> {<express>} [#cost>N] -n <count> -x <expand> -m 1 --timeout <s>
	KindTrace   Kind = "trace"   // trace <class> <method> [#cost>N] -n <count> -m 1 --timeout <s>
	KindStack   Kind = "stack"   // stack <class> <method> [#cost>N] -n <count> -m 1 --timeout <s>
	KindMonitor Kind = "monitor" // monitor <class> <method> [#cost>N] -c <cycle> -n <count> -m 1 --timeout <s>
	KindJad     Kind = "jad"     // jad --source-only <class> [method]
)

const (
	// DefaultExecTimeout is used when Policy.ExecTimeout is zero.
	DefaultExecTimeout = 30 * time.Second
	// MaxExecTimeout bounds execTimeout. Arthas keeps running a job after the
	// HTTP connection is gone, until execTimeout expires.
	MaxExecTimeout = 60 * time.Second
	// MaxTop is the largest thread count for KindThreadTop.
	MaxTop = 10
)

// Limits of the L2 commands (plan section 4). The Policy fields can tighten the defaults but not
// loosen them; ObjectSizeLimit may also be raised, up to its maximum.
const (
	// MaxCount is the largest -n: the number of results after which the job ends.
	MaxCount = 5
	// MaxExpand is the largest watch -x: the depth to which objects are expanded.
	MaxExpand = 2
	// MaxMinCost bounds the #cost condition, in milliseconds.
	MaxMinCost = 3600000
	// DefaultEnhance and MaxEnhance are the time an enhancement lasts (--timeout). Arthas
	// schedules the end of the job when the enhancement is done; the job also ends after -n
	// results. Arthas ignores execTimeout for a background job.
	DefaultEnhance = 30 * time.Second
	MaxEnhance     = 30 * time.Second
	// DefaultMaxMethods is the most methods one enhancement may affect; every overload and
	// bridge method of the name counts.
	DefaultMaxMethods = 5
	// DefaultObjectSizeLimit, MinObjectSizeLimit and MaxObjectSizeLimit bound the text of one
	// watch value (Arthas option object-size-limit), in bytes. watch -M has no effect on the
	// results of the HTTP API.
	DefaultObjectSizeLimit = 8 << 10
	MinObjectSizeLimit     = 256
	MaxObjectSizeLimit     = 64 << 10
)

// ForbiddenClassPrefixes are packages whose classes an L2 command never touches, whatever the
// policy allows: the runtime of the JVM and Arthas itself.
var ForbiddenClassPrefixes = []string{"java.", "javax.", "jdk.", "sun.", "com.sun.", "com.taobao.arthas.", "com.alibaba.arthas."}

// watchExpressions are the values of Request.Express: the subsets of the three advice fields, in
// a fixed order. A field missing from the advice prints as null.
var watchExpressions = []string{
	"params", "returnObj", "throwExp", "params,returnObj", "params,throwExp", "returnObj,throwExp", "params,returnObj,throwExp",
}

// WatchExpressions returns the values Request.Express accepts.
func WatchExpressions() []string { return slices.Clone(watchExpressions) }

// Request is the caller's choice of command and its structured arguments.
// Fields that do not belong to Kind must stay empty.
type Request struct {
	Kind     Kind
	Top      int    // KindThreadTop: 1 to MaxTop
	ThreadID int64  // KindThreadInfo: positive
	Class    string // KindClassInfo, KindMethodInfo: binary name without wildcards
	Method   string // KindMethodInfo, KindJad: optional Java identifier; the L2 enhancing kinds: required
	Key      string // KindSysprop: one of Policy.SyspropKeys
	Express  string // KindWatch: one of WatchExpressions
	Expand   int    // KindWatch: -x, 1 to MaxExpand
	Count    int    // KindWatch, KindTrace, KindStack, KindMonitor: -n, 1 to MaxCount
	MinCost  int64  // KindWatch, KindTrace, KindStack, KindMonitor: optional condition #cost>MinCost, in milliseconds
	Cycle    int    // KindMonitor: -c, the seconds of one statistics period
}

// Policy is trusted configuration.
type Policy struct {
	// SyspropKeys are the system property keys KindSysprop may read.
	SyspropKeys []string
	// ExecTimeout is the execTimeout of the command; zero selects
	// DefaultExecTimeout. At most MaxExecTimeout.
	ExecTimeout time.Duration
	// ClassPrefixes are the package prefixes, each ending with a dot, that the class of an L2
	// command must start with. Empty refuses every L2 command.
	ClassPrefixes []string
	// Enhance is the time an enhancement lasts, in whole seconds; zero selects DefaultEnhance.
	Enhance time.Duration
	// MaxMethods is the most methods one enhancement may affect; zero selects DefaultMaxMethods.
	MaxMethods int
	// ObjectSizeLimit bounds one watch value, in bytes; zero selects DefaultObjectSizeLimit.
	ObjectSizeLimit int
}

// PreCheck names a check the caller must make before it sends the command.
type PreCheck string

// PreCheckThreadCount: the live thread count of the target (hsperfdata
// java.threads.live) must be within the configured limit. thread -b walks the
// monitors of every thread in one safepoint, so its pause grows with the
// thread count.
const PreCheckThreadCount PreCheck = "thread_count"

// PreCheckCPU: the CPU use of the target, over a few seconds and relative to its CPU limit, must
// be below the configured share. The first seconds of an enhancement multiply the CPU use of the
// JVM (plan section 3.3), so an L2 command needs room.
const PreCheckCPU PreCheck = "cpu_usage"

// Command is a validated command.
type Command struct {
	Kind Kind
	// Name is the Arthas command name, for AgentConfig.Enabled.
	Name string
	// Text is the command line sent to Arthas. It is built from fixed words
	// and validated arguments only.
	Text        string
	ExecTimeout time.Duration
	PreChecks   []PreCheck
	// Level is 1 for the commands that only read and 2 for those that change classes.
	Level int
	// Setup are commands to send in the same session before Text. Build puts only options
	// commands with fixed values there.
	Setup []string
	// Enhance is the --timeout of an enhancing command, and zero for every other command. An
	// enhancing command runs as a background job, so that its enhancer result can be checked
	// as soon as it arrives.
	Enhance time.Duration
	// MaxMethods is the most methods the enhancement may affect.
	MaxMethods int

	// built is set by Build; Client.Exec refuses a Command without it.
	built bool
}

// Enabled returns the Arthas commands the server must accept for this command, for
// AgentConfig.Enabled.
func (c Command) Enabled() []string {
	if len(c.Setup) > 0 {
		return []string{c.Name, "options"}
	}
	return []string{c.Name}
}

var allKinds = []Kind{
	KindDashboard, KindThreadTop, KindThreadBlocking, KindThreadInfo, KindMemory, KindJVM, KindClassInfo,
	KindMethodInfo, KindClassLoaderTree, KindClassLoaderList, KindSysprop, KindVersion,
	KindWatch, KindTrace, KindStack, KindMonitor, KindJad,
}

// paused are the kinds that Build still accepts but that are not offered, with the reason. Their
// parsing and rendering stay, so that a kind can return once its problem is solved.
var paused = map[Kind]string{
	KindLogger: "after logger the class loader of Arthas is not unloaded, so every call keeps about 12 MiB of " +
		"metaspace until the JVM restarts; the command stays paused until the cause is known",
}

// Level returns 2 for the kinds that change classes (watch, trace, stack, monitor and jad) and 1
// for every other kind.
func (k Kind) Level() int {
	if k.Enhances() || k == KindJad {
		return 2
	}
	return 1
}

// Enhances reports whether the kind enhances a method and runs as a background job: watch,
// trace, stack and monitor.
func (k Kind) Enhances() bool {
	return k == KindWatch || k == KindTrace || k == KindStack || k == KindMonitor
}

// Kinds returns every offered Kind; the paused kinds are not among them.
func Kinds() []Kind { return slices.Clone(allKinds) }

// Paused returns why a kind is not offered, and false for a kind that is offered or unknown.
func Paused(k Kind) (reason string, ok bool) {
	reason, ok = paused[k]
	return reason, ok
}

// Build validates the request against the policy and returns the command.
// The command text is assembled from fixed words and arguments that matched a
// strict pattern; nothing the caller wrote is passed on otherwise.
func Build(req Request, pol Policy) (Command, error) {
	timeout, err := pol.timeout()
	if err != nil {
		return Command{}, err
	}
	cmd := Command{Kind: req.Kind, ExecTimeout: timeout, Level: 1, built: true}
	rest := req // the fields the kind does not use; they must be empty
	rest.Kind = ""
	switch req.Kind {
	case KindDashboard:
		cmd.Name, cmd.Text = "dashboard", "dashboard -n 1"
	case KindThreadTop:
		rest.Top = 0
		if req.Top < 1 || req.Top > MaxTop {
			return Command{}, fmt.Errorf("arthas: top %d is out of range 1-%d", req.Top, MaxTop)
		}
		cmd.Name, cmd.Text = "thread", "thread -n "+strconv.Itoa(req.Top)
	case KindThreadBlocking:
		cmd.Name, cmd.Text = "thread", "thread -b"
		cmd.PreChecks = []PreCheck{PreCheckThreadCount}
	case KindThreadInfo:
		rest.ThreadID = 0
		if req.ThreadID < 1 {
			return Command{}, fmt.Errorf("arthas: thread id %d is not positive", req.ThreadID)
		}
		cmd.Name, cmd.Text = "thread", "thread "+strconv.FormatInt(req.ThreadID, 10)
	case KindMemory:
		cmd.Name, cmd.Text = "memory", "memory"
	case KindJVM:
		cmd.Name, cmd.Text = "jvm", "jvm"
	case KindClassInfo:
		rest.Class = ""
		if err := checkClassName(req.Class); err != nil {
			return Command{}, err
		}
		cmd.Name, cmd.Text = "sc", "sc -d "+req.Class
	case KindMethodInfo:
		rest.Class, rest.Method = "", ""
		if err := checkClassName(req.Class); err != nil {
			return Command{}, err
		}
		cmd.Name, cmd.Text = "sm", "sm -d "+req.Class
		if req.Method != "" {
			if err := checkIdentifier("method name", req.Method); err != nil {
				return Command{}, err
			}
			cmd.Text += " " + req.Method
		}
	case KindClassLoaderTree:
		cmd.Name, cmd.Text = "classloader", "classloader -t"
	case KindClassLoaderList:
		cmd.Name, cmd.Text = "classloader", "classloader -l"
	case KindLogger:
		cmd.Name, cmd.Text = "logger", "logger"
	case KindSysprop:
		rest.Key = ""
		for _, k := range pol.SyspropKeys {
			if !propertyKeyRE.MatchString(k) || len(k) > maxNameLength {
				return Command{}, fmt.Errorf("arthas: sysprop allowlist entry %q is not a plain property key", k)
			}
		}
		if !slices.Contains(pol.SyspropKeys, req.Key) {
			return Command{}, fmt.Errorf("arthas: system property %q is not in the allowlist", req.Key)
		}
		cmd.Name, cmd.Text = "sysprop", "sysprop "+req.Key
	case KindVersion:
		cmd.Name, cmd.Text = "version", "version"
	case KindWatch, KindTrace, KindStack, KindMonitor:
		rest.Class, rest.Method, rest.Count, rest.MinCost = "", "", 0, 0
		if req.Kind == KindWatch {
			rest.Express, rest.Expand = "", 0
		}
		if req.Kind == KindMonitor {
			rest.Cycle = 0
		}
		if err := buildEnhancer(&cmd, req, pol); err != nil {
			return Command{}, err
		}
	case KindJad:
		rest.Class, rest.Method = "", ""
		if err := checkL2Class(req.Class, pol.ClassPrefixes); err != nil {
			return Command{}, err
		}
		cmd.Name, cmd.Text, cmd.Level = "jad", "jad --source-only "+req.Class, 2
		cmd.PreChecks = []PreCheck{PreCheckCPU}
		if req.Method != "" {
			if err := checkIdentifier("method name", req.Method); err != nil {
				return Command{}, err
			}
			cmd.Text += " " + req.Method
		}
	default:
		return Command{}, fmt.Errorf("arthas: unknown command kind %q", req.Kind)
	}
	if rest != (Request{}) {
		return Command{}, fmt.Errorf("arthas: %s does not take these arguments: %s", req.Kind, setFields(rest))
	}
	return cmd, nil
}

// buildEnhancer fills cmd for watch, trace, stack and monitor. Every word of the command is
// fixed or a validated value; the condition is generated from an integer.
func buildEnhancer(cmd *Command, req Request, pol Policy) error {
	enhance, err := pol.enhance()
	if err != nil {
		return err
	}
	maxMethods, err := pol.maxMethods()
	if err != nil {
		return err
	}
	if err := checkL2Class(req.Class, pol.ClassPrefixes); err != nil {
		return err
	}
	if err := checkIdentifier("method name", req.Method); err != nil {
		return err
	}
	if req.Count < 1 || req.Count > MaxCount {
		return fmt.Errorf("arthas: count %d is out of range 1-%d", req.Count, MaxCount)
	}
	if req.MinCost < 0 || req.MinCost > MaxMinCost {
		return fmt.Errorf("arthas: minimum cost %d ms is out of range 0-%d", req.MinCost, MaxMinCost)
	}
	seconds := int(enhance / time.Second)
	words := []string{string(req.Kind), req.Class, req.Method}
	setup := []string{"options disable-sub-class true"}
	if req.Kind == KindWatch {
		if !slices.Contains(watchExpressions, req.Express) {
			return fmt.Errorf("arthas: watch expression %q is not one of: %s", clip(req.Express), strings.Join(watchExpressions, "; "))
		}
		if req.Expand < 1 || req.Expand > MaxExpand {
			return fmt.Errorf("arthas: expand %d is out of range 1-%d", req.Expand, MaxExpand)
		}
		size, err := pol.objectSizeLimit()
		if err != nil {
			return err
		}
		words = append(words, "{"+req.Express+"}")
		setup = append(setup, "options object-size-limit "+strconv.Itoa(size))
	}
	if req.MinCost > 0 {
		words = append(words, "#cost>"+strconv.FormatInt(req.MinCost, 10))
	}
	if req.Kind == KindMonitor {
		// Arthas writes a period about 0.1 seconds after it ended; the last one has to come
		// before --timeout ends the job.
		if req.Cycle < 1 || req.Cycle >= seconds || req.Count*req.Cycle >= seconds {
			return fmt.Errorf("arthas: monitor count × cycle (%d × %ds) must be shorter than the enhancement time %s", req.Count, req.Cycle, enhance)
		}
		words = append(words, "-c", strconv.Itoa(req.Cycle))
	}
	words = append(words, "-n", strconv.Itoa(req.Count))
	if req.Kind == KindWatch {
		words = append(words, "-x", strconv.Itoa(req.Expand))
	}
	words = append(words, "-m", "1", "--timeout", strconv.Itoa(seconds))
	cmd.Name, cmd.Text, cmd.Level = string(req.Kind), strings.Join(words, " "), 2
	cmd.Setup, cmd.Enhance, cmd.MaxMethods = setup, enhance, maxMethods
	cmd.PreChecks = []PreCheck{PreCheckCPU}
	return nil
}

func (p Policy) enhance() (time.Duration, error) {
	switch {
	case p.Enhance == 0:
		return DefaultEnhance, nil
	case p.Enhance < time.Second || p.Enhance > MaxEnhance || p.Enhance%time.Second != 0:
		return 0, fmt.Errorf("arthas: enhancement time %s is not a whole number of seconds from 1s to %s", p.Enhance, MaxEnhance)
	}
	return p.Enhance, nil
}

func (p Policy) maxMethods() (int, error) {
	switch {
	case p.MaxMethods == 0:
		return DefaultMaxMethods, nil
	case p.MaxMethods < 1 || p.MaxMethods > DefaultMaxMethods:
		return 0, fmt.Errorf("arthas: maximum method count %d is out of range 1-%d", p.MaxMethods, DefaultMaxMethods)
	}
	return p.MaxMethods, nil
}

func (p Policy) objectSizeLimit() (int, error) {
	switch {
	case p.ObjectSizeLimit == 0:
		return DefaultObjectSizeLimit, nil
	case p.ObjectSizeLimit < MinObjectSizeLimit || p.ObjectSizeLimit > MaxObjectSizeLimit:
		return 0, fmt.Errorf("arthas: object size limit %d is out of range %d-%d bytes", p.ObjectSizeLimit, MinObjectSizeLimit, MaxObjectSizeLimit)
	}
	return p.ObjectSizeLimit, nil
}

func (p Policy) timeout() (time.Duration, error) {
	switch {
	case p.ExecTimeout == 0:
		return DefaultExecTimeout, nil
	case p.ExecTimeout < 0 || p.ExecTimeout > MaxExecTimeout:
		return 0, fmt.Errorf("arthas: exec timeout %s is out of range (0, %s]", p.ExecTimeout, MaxExecTimeout)
	}
	return p.ExecTimeout, nil
}

const maxNameLength = 255

var (
	// A Java binary name: identifier segments separated by dots; "$" joins
	// nested classes. No wildcard, no slash and no regular expression
	// characters, so sc and sm match the name literally.
	classNameRE   = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*$`)
	identifierRE  = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
	propertyKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*)*$`)
	// A package prefix: identifier segments, each followed by a dot.
	classPrefixRE = regexp.MustCompile(`^([A-Za-z_$][A-Za-z0-9_$]*\.)+$`)
)

// CheckClassPrefix validates one entry of Policy.ClassPrefixes: a package prefix that ends with a
// dot and is not inside a forbidden package.
func CheckClassPrefix(prefix string) error {
	if len(prefix) > maxNameLength || !classPrefixRE.MatchString(prefix) {
		return fmt.Errorf("arthas: class prefix %q is not a package name followed by a dot", clip(prefix))
	}
	for _, f := range ForbiddenClassPrefixes {
		if strings.HasPrefix(prefix, f) {
			return fmt.Errorf("arthas: class prefix %q is inside %s, whose classes are never enhanced", clip(prefix), f)
		}
	}
	return nil
}

// checkL2Class checks the class of an L2 command: a binary name without wildcards, outside the
// forbidden packages and inside one of the allowed prefixes.
func checkL2Class(name string, prefixes []string) error {
	if err := checkClassName(name); err != nil {
		return err
	}
	for _, f := range ForbiddenClassPrefixes {
		if strings.HasPrefix(name, f) {
			return fmt.Errorf("arthas: class %q is inside %s, whose classes are never enhanced", clip(name), f)
		}
	}
	if len(prefixes) == 0 {
		return errors.New("arthas: no class prefix is allowed, so no L2 command can run")
	}
	for _, p := range prefixes {
		if err := CheckClassPrefix(p); err != nil {
			return err
		}
	}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return nil
		}
	}
	return fmt.Errorf("arthas: class %q does not start with an allowed prefix (%s)", clip(name), strings.Join(prefixes, ", "))
}

func checkClassName(name string) error {
	if len(name) > maxNameLength || !classNameRE.MatchString(name) {
		return fmt.Errorf("arthas: %q is not a class binary name without wildcards", clip(name))
	}
	return nil
}

func checkIdentifier(what, name string) error {
	if len(name) > maxNameLength || !identifierRE.MatchString(name) {
		return fmt.Errorf("arthas: %q is not a Java identifier (%s)", clip(name), what)
	}
	return nil
}

// clip shortens a rejected value for the error message.
func clip(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

func setFields(r Request) string {
	var names []string
	if r.Top != 0 {
		names = append(names, "top")
	}
	if r.ThreadID != 0 {
		names = append(names, "thread id")
	}
	if r.Class != "" {
		names = append(names, "class")
	}
	if r.Method != "" {
		names = append(names, "method")
	}
	if r.Key != "" {
		names = append(names, "key")
	}
	if r.Express != "" {
		names = append(names, "express")
	}
	if r.Expand != 0 {
		names = append(names, "expand")
	}
	if r.Count != 0 {
		names = append(names, "count")
	}
	if r.MinCost != 0 {
		names = append(names, "minimum cost")
	}
	if r.Cycle != 0 {
		names = append(names, "cycle")
	}
	return strings.Join(names, ", ")
}

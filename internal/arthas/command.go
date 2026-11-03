package arthas

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Kind names one of the fixed read-only commands (level L1: the JVM is
// attached but no class is enhanced).
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

// Request is the caller's choice of command and its structured arguments.
// Fields that do not belong to Kind must stay empty.
type Request struct {
	Kind     Kind
	Top      int    // KindThreadTop: 1 to MaxTop
	ThreadID int64  // KindThreadInfo: positive
	Class    string // KindClassInfo, KindMethodInfo: binary name without wildcards
	Method   string // KindMethodInfo: optional Java identifier
	Key      string // KindSysprop: one of Policy.SyspropKeys
}

// Policy is trusted configuration.
type Policy struct {
	// SyspropKeys are the system property keys KindSysprop may read.
	SyspropKeys []string
	// ExecTimeout is the execTimeout of the command; zero selects
	// DefaultExecTimeout. At most MaxExecTimeout.
	ExecTimeout time.Duration
}

// PreCheck names a check the caller must make before it sends the command.
type PreCheck string

// PreCheckThreadCount: the live thread count of the target (hsperfdata
// java.threads.live) must be within the configured limit. thread -b walks the
// monitors of every thread in one safepoint, so its pause grows with the
// thread count.
const PreCheckThreadCount PreCheck = "thread_count"

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

	// built is set by Build; Client.Exec refuses a Command without it.
	built bool
}

var allKinds = []Kind{
	KindDashboard, KindThreadTop, KindThreadBlocking, KindThreadInfo, KindMemory, KindJVM, KindClassInfo,
	KindMethodInfo, KindClassLoaderTree, KindClassLoaderList, KindSysprop, KindVersion,
}

// paused are the kinds that Build still accepts but that are not offered, with the reason. Their
// parsing and rendering stay, so that a kind can return once its problem is solved.
var paused = map[Kind]string{
	KindLogger: "after logger the class loader of Arthas is not unloaded, so every call keeps about 12 MiB of " +
		"metaspace until the JVM restarts; the command stays paused until the cause is known",
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
	cmd := Command{Kind: req.Kind, ExecTimeout: timeout, built: true}
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
	default:
		return Command{}, fmt.Errorf("arthas: unknown command kind %q", req.Kind)
	}
	if rest != (Request{}) {
		return Command{}, fmt.Errorf("arthas: %s does not take these arguments: %s", req.Kind, setFields(rest))
	}
	return cmd, nil
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
)

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
	return strings.Join(names, ", ")
}

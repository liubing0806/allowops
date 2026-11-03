package arthas

import (
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// MaxArgumentBytes is the longest "<arthas-agent.jar>=<options>" string the
// HotSpot attach "load" request accepted in the measurements; one byte more
// made the JVM answer with an empty reply.
const MaxArgumentBytes = 1024

const (
	// minPasswordLength rejects short passwords. NewPassword returns
	// passwordLength characters.
	minPasswordLength = 16
	passwordLength    = 32
	passwordAlphabet  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

// allCommands holds every @Name value of the command classes in Arthas 4.3.5,
// sorted. BuiltinCommandPack registers all of them except groovy; classloader-
// metaspace only when the JVM has jdk.jfr. disabledCommands is compared against
// exactly these names. The classes declare auth with a constant and
// classloader-metaspace with a fully qualified annotation, so a plain search
// for @Name("...") does not find them.
var allCommands = []string{
	"auth", "base64", "cat", "classloader", "classloader-metaspace", "cls", "dashboard", "dump", "echo",
	"getstatic", "grep", "groovy", "heapdump", "help", "history", "jad", "jfr", "july", "jvm", "keymap",
	"line", "logger", "mbean", "mc", "memory", "monitor", "ognl", "options", "perfcounter", "profiler",
	"pwd", "redefine", "reset", "retransform", "sc", "session", "sm", "stack", "stop", "sysenv", "sysprop",
	"tee", "thanks", "thread", "trace", "tt", "version", "vmoption", "vmtool", "watch",
}

// alwaysEnabled are the commands the clean-up sequence sends. stop is the only
// way to end the Arthas server and reset is the only way to undo an
// enhancement, so neither can be disabled.
var alwaysEnabled = []string{"reset", "stop"}

// AgentConfig describes one Arthas server to load into a target JVM. Paths are
// the paths as the target JVM sees them.
type AgentConfig struct {
	AgentJar string
	CoreJar  string
	HTTPPort int
	Password string
	// Enabled lists the Arthas commands the call needs. reset and stop stay
	// enabled whatever the list says, because the clean-up sequence uses them.
	Enabled        []string
	SessionTimeout time.Duration
}

// AllCommands returns every command name Arthas 4.3.5 can register, sorted.
func AllCommands() []string { return slices.Clone(allCommands) }

// DisabledCommands returns the sorted names that disabledCommands must list so
// that only the given commands (and reset and stop) stay enabled.
func DisabledCommands(enabled []string) ([]string, error) {
	keep := map[string]bool{}
	for _, name := range alwaysEnabled {
		keep[name] = true
	}
	for _, name := range enabled {
		if _, ok := slices.BinarySearch(allCommands, name); !ok {
			return nil, fmt.Errorf("arthas: unknown command name %q", name)
		}
		keep[name] = true
	}
	disabled := make([]string, 0, len(allCommands))
	for _, name := range allCommands {
		if !keep[name] {
			disabled = append(disabled, name)
		}
	}
	return disabled, nil
}

// NewPassword returns a random password of letters and digits. Arthas decodes
// the whole agent argument as a URL, so the password must not contain "+" or
// "%"; it must not contain ";" or "=" either.
func NewPassword() (string, error) {
	// 248 = 4*62 is the largest multiple of the alphabet size below 256;
	// bytes at or above it are dropped so that every letter is equally likely.
	const limit = 248
	out := make([]byte, 0, passwordLength)
	buf := make([]byte, 2*passwordLength)
	for len(out) < passwordLength {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("arthas: read random bytes: %w", err)
		}
		for _, b := range buf {
			if b < limit && len(out) < passwordLength {
				out = append(out, passwordAlphabet[int(b)%len(passwordAlphabet)])
			}
		}
	}
	return string(out), nil
}

// checkPath rejects every byte that Arthas would read differently from what
// the caller wrote. It URL-decodes the argument ("+" becomes a space, "%xx" a
// byte), splits it at ";" and "=", and treats "\" as an escape in the key=value
// part.
func checkPath(what, p string) error {
	if p == "" {
		return fmt.Errorf("arthas: %s is empty", what)
	}
	if p[0] != '/' {
		return fmt.Errorf("arthas: %s must be an absolute path", what)
	}
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c < 0x20 || c == 0x7f:
			return fmt.Errorf("arthas: %s contains a control character at byte %d", what, i)
		case strings.IndexByte("%+;=\\", c) >= 0:
			return fmt.Errorf("arthas: %s contains %q at byte %d, which Arthas would read differently", what, c, i)
		}
	}
	return nil
}

func checkPassword(p string) error {
	if len(p) < minPasswordLength {
		return fmt.Errorf("arthas: password must have at least %d characters", minPasswordLength)
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return fmt.Errorf("arthas: password must contain letters and digits only (byte %d)", i)
		}
	}
	return nil
}

func (c AgentConfig) validate() error {
	if err := checkPath("agent jar path", c.AgentJar); err != nil {
		return err
	}
	if err := checkPath("core jar path", c.CoreJar); err != nil {
		return err
	}
	if c.HTTPPort < 1 || c.HTTPPort > 65535 {
		return fmt.Errorf("arthas: http port %d is out of range 1-65535", c.HTTPPort)
	}
	if err := checkPassword(c.Password); err != nil {
		return err
	}
	if c.SessionTimeout <= 0 {
		return errors.New("arthas: session timeout must be positive")
	}
	return nil
}

// Options returns "<core jar>;key=value;..." for the agent argument.
//
// The argument fixes telnetPort=-1 (no telnet listener), ip=127.0.0.1 and
// localConnectionNonAuth=false (without it connections from 127.0.0.1 need no
// password). It never carries mcpEndpoint: Arthas drops every key whose value
// is blank, so "mcpEndpoint=" leaves the MCP service on. The MCP service is
// switched off by removing arthas.mcpEndpoint and arthas.mcpProtocol from the
// arthas.properties file next to the jars.
func (c AgentConfig) Options() (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	disabled, err := DisabledCommands(c.Enabled)
	if err != nil {
		return "", err
	}
	timeout := int((c.SessionTimeout + time.Second - 1) / time.Second)
	return c.CoreJar +
		";telnetPort=-1" +
		";httpPort=" + strconv.Itoa(c.HTTPPort) +
		";ip=127.0.0.1" +
		";password=" + c.Password +
		";localConnectionNonAuth=false" +
		";disabledCommands=" + strings.Join(disabled, ",") +
		";sessionTimeout=" + strconv.Itoa(timeout), nil
}

// Argument returns "<agent jar>=<options>", the string sent after
// "load instrument false", and checks MaxArgumentBytes.
func (c AgentConfig) Argument() (string, error) {
	options, err := c.Options()
	if err != nil {
		return "", err
	}
	if err := CheckArgumentLength(c.AgentJar, options); err != nil {
		return "", err
	}
	return c.AgentJar + "=" + options, nil
}

// CheckArgumentLength reports an error when "<agentJar>=<options>" is longer
// than MaxArgumentBytes bytes.
func CheckArgumentLength(agentJar, options string) error {
	if n := len(agentJar) + 1 + len(options); n > MaxArgumentBytes {
		return fmt.Errorf("arthas: agent argument has %d bytes, the limit is %d", n, MaxArgumentBytes)
	}
	return nil
}

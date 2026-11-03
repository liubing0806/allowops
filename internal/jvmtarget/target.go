// Package jvmtarget finds a running JVM from a signed allowlist entry and reads
// its hsperfdata without attaching to it or signalling it. The caller names a
// target; it never supplies a pid or a path.
package jvmtarget

import (
	"errors"
	"fmt"
	"regexp"
	"unicode/utf8"
)

// Target is one allowlist entry. Exactly one of SystemdUnit or
// Container+MainClass is set.
type Target struct {
	Name        string `json:"-"`
	SystemdUnit string `json:"systemd_unit,omitempty"`
	Container   string `json:"container,omitempty"`
	// MainClass is the first word of the JVM's sun.rt.javaCommand: the main
	// class, or the jar path of a -jar launch.
	MainClass string `json:"main_class,omitempty"`
}

const (
	maxUnitLen      = 128
	maxContainerLen = 128
	maxMainClassLen = 512
)

var (
	namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	// A unit name never starts with "-", so it cannot be read as a systemctl option.
	unitPattern = regexp.MustCompile(`^[A-Za-z0-9:_@][A-Za-z0-9:_.@-]*\.service$`)
	// Docker's own rule for container names; it also keeps the name from altering the request path.
	containerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
)

// Validate checks the entry's syntax.
func (t Target) Validate() error {
	if !namePattern.MatchString(t.Name) {
		return fmt.Errorf("target name %q must match %s", t.Name, namePattern)
	}
	switch {
	case t.SystemdUnit != "" && (t.Container != "" || t.MainClass != ""):
		return fmt.Errorf("target %s: set either systemd_unit or container with main_class", t.Name)
	case t.SystemdUnit != "":
		if len(t.SystemdUnit) > maxUnitLen || !unitPattern.MatchString(t.SystemdUnit) {
			return fmt.Errorf("target %s: systemd_unit must be a service unit name of at most %d bytes (letters, digits and : _ . @ -)", t.Name, maxUnitLen)
		}
	case t.Container != "" && t.MainClass != "":
		if len(t.Container) > maxContainerLen || !containerPattern.MatchString(t.Container) {
			return fmt.Errorf("target %s: container must be a Docker container name of at most %d bytes", t.Name, maxContainerLen)
		}
		if err := validMainClass(t.MainClass); err != nil {
			return fmt.Errorf("target %s: %w", t.Name, err)
		}
	case t.Container != "" || t.MainClass != "":
		return fmt.Errorf("target %s: container and main_class must be set together", t.Name)
	default:
		return fmt.Errorf("target %s: set systemd_unit, or container with main_class", t.Name)
	}
	return nil
}

func validMainClass(s string) error {
	if len(s) == 0 || len(s) > maxMainClassLen || !utf8.ValidString(s) {
		return fmt.Errorf("main_class must be 1..%d bytes of UTF-8", maxMainClassLen)
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] == 0x7f {
			return errors.New("main_class must not contain spaces or control characters: it is the first word of the JVM's command")
		}
	}
	return nil
}

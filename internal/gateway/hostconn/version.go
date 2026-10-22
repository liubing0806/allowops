package hostconn

import (
	"fmt"
	"github.com/Masterminds/semver/v3"
)

// CheckVersion uses strict SemVer 2.0 (including prerelease precedence).
func CheckVersion(gateway, agent string) error {
	g, err := semver.StrictNewVersion(gateway)
	if err != nil {
		return fmt.Errorf("invalid gateway SemVer")
	}
	a, err := semver.StrictNewVersion(agent)
	if err != nil {
		return fmt.Errorf("invalid agent SemVer")
	}
	if a.GreaterThan(g) || a.Major() > g.Major() || (g.Major() > 0 && a.Major() < g.Major()-1) {
		return fmt.Errorf("agent version unsupported")
	}
	return nil
}

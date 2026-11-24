package job

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ApprovalConfig struct {
	DefaultTTL           time.Duration `yaml:"default_ttl"`
	MaxTTL               time.Duration `yaml:"max_ttl"`
	MaxPendingPerSubject int           `yaml:"max_pending_per_subject"`
	MaxPendingGlobal     int           `yaml:"max_pending_global"`
	SweepInterval        time.Duration `yaml:"sweep_interval"`
	ConsoleBaseURL       string        `yaml:"console_base_url"`
}

func DefaultApprovalConfig() ApprovalConfig {
	return ApprovalConfig{
		DefaultTTL: 30 * time.Minute, MaxTTL: 24 * time.Hour,
		MaxPendingPerSubject: 10, MaxPendingGlobal: 1000, SweepInterval: 15 * time.Second,
	}
}

func (c ApprovalConfig) Validate() error {
	if c.DefaultTTL < time.Minute || c.DefaultTTL > c.MaxTTL || c.MaxTTL > 168*time.Hour {
		return errors.New("approvals requires 1m <= default_ttl <= max_ttl <= 168h")
	}
	if c.MaxPendingPerSubject < 1 || c.MaxPendingPerSubject > 100 ||
		c.MaxPendingGlobal < 1 || c.MaxPendingGlobal > 10000 {
		return errors.New("approvals pending limits must be in 1..100 per subject and 1..10000 globally")
	}
	if c.SweepInterval < time.Second || c.SweepInterval > 5*time.Minute {
		return errors.New("approvals.sweep_interval must be in 1s..5m")
	}
	if c.ConsoleBaseURL != "" {
		u, err := url.Parse(c.ConsoleBaseURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
			u.Path != "" || strings.HasSuffix(u.Host, ":") || strings.ContainsAny(c.ConsoleBaseURL, "?#") {
			return errors.New("approvals.console_base_url must be an HTTPS origin")
		}
		if port := u.Port(); port != "" {
			if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
				return errors.New("approvals.console_base_url has an invalid port")
			}
		}
	}
	return nil
}

// ConfigureApprovals sets approval limits before Start or Handler.
func (s *Service) ConfigureApprovals(c ApprovalConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	s.approvals = c
	return nil
}

func (s *Service) approvalConfig() ApprovalConfig {
	if s.approvals == (ApprovalConfig{}) {
		return DefaultApprovalConfig()
	}
	return s.approvals
}

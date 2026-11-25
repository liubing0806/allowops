package main

import (
	"strings"
	"testing"
	"time"
)

func TestApprovalGatewayConfiguration(t *testing.T) {
	cfg, err := decodeConfig(strings.NewReader("identity:\n  origin: https://ops.example.test\n"))
	if err != nil || cfg.Approvals.DefaultTTL != 30*time.Minute || cfg.Approvals.MaxTTL != 24*time.Hour ||
		cfg.Approvals.MaxPendingPerSubject != 10 || cfg.Approvals.MaxPendingGlobal != 1000 ||
		cfg.Approvals.SweepInterval != 15*time.Second || cfg.Approvals.ConsoleBaseURL != "https://ops.example.test" {
		t.Fatalf("default approval config=%+v err=%v", cfg.Approvals, err)
	}
	cfg, err = decodeConfig(strings.NewReader(`approvals:
  default_ttl: 1m
  max_ttl: 168h
  max_pending_per_subject: 100
  max_pending_global: 10000
  sweep_interval: 5m
  console_base_url: https://console.example.test:8443
`))
	if err != nil || cfg.Approvals.DefaultTTL != time.Minute || cfg.Approvals.MaxTTL != 168*time.Hour ||
		cfg.Approvals.ConsoleBaseURL != "https://console.example.test:8443" {
		t.Fatalf("custom approval config=%+v err=%v", cfg.Approvals, err)
	}
	for _, invalid := range []string{
		"unknown: true", "default_ttl: 59s", "max_ttl: 29m", "max_ttl: 169h",
		"max_pending_per_subject: 0", "max_pending_per_subject: 101", "max_pending_global: 0", "max_pending_global: 10001",
		"sweep_interval: 999ms", "sweep_interval: 301s", "console_base_url: http://console.example.test",
		"console_base_url: https://user@console.example.test", "console_base_url: https://console.example.test/path",
		"console_base_url: https://console.example.test:65536", "console_base_url: https://console.example.test:",
		"console_base_url: https://console.example.test?secret=value", "console_base_url: https://console.example.test#section",
	} {
		t.Run(invalid, func(t *testing.T) {
			if _, err := decodeConfig(strings.NewReader("approvals:\n  " + invalid + "\n")); err == nil {
				t.Fatal("expected approval configuration error")
			}
		})
	}
}

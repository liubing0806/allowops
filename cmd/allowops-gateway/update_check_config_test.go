package main

import (
	"strings"
	"testing"
	"time"
)

func TestUpdateCheckConfiguration(t *testing.T) {
	cfg, err := decodeConfig(strings.NewReader("address: :8443\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UpdateCheck.Enabled || cfg.UpdateCheck.Interval != 24*time.Hour || cfg.UpdateCheck.URL != "https://liubing0806.github.io/allowops/version.json" {
		t.Fatalf("defaults %+v", cfg.UpdateCheck)
	}
	cfg, err = decodeConfig(strings.NewReader("update_check:\n  enabled: true\n  url: https://mirror.internal/version.json\n  interval: 2h\n"))
	if err != nil || !cfg.UpdateCheck.Enabled || cfg.UpdateCheck.Interval != 2*time.Hour || cfg.UpdateCheck.URL != "https://mirror.internal/version.json" {
		t.Fatalf("custom %+v %v", cfg.UpdateCheck, err)
	}
	for name, yaml := range map[string]string{
		"http url":     "update_check:\n  enabled: true\n  url: http://mirror.internal/version.json\n",
		"userinfo":     "update_check:\n  enabled: true\n  url: https://u:p@mirror.internal/version.json\n",
		"short":        "update_check:\n  enabled: true\n  interval: 30m\n",
		"unknown key":  "update_check:\n  enabled: true\n  proxy: http://x\n",
		"unknown root": "update_checks:\n  enabled: true\n",
	} {
		if _, err := decodeConfig(strings.NewReader(yaml)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

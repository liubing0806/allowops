package main

import (
	"strings"
	"testing"
)

func TestMCPConfiguration(t *testing.T) {
	cfg, err := decodeConfig(strings.NewReader("address: :8443\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MCP.Mode != "flat" || !cfg.MCP.AutoThreshold.set || cfg.MCP.AutoThreshold.value != 40 {
		t.Fatalf("defaults %+v", cfg.MCP)
	}
	for yaml, want := range map[string]struct {
		mode      string
		threshold int
	}{
		"mcp:\n  mode: progressive\n":                      {"progressive", 40},
		"mcp:\n  mode: auto\n  auto_threshold: 1\n":        {"auto", 1},
		"mcp:\n  mode: auto\n  auto_threshold: 1000\n":     {"auto", 1000},
		"mcp:\n  mode: flat\n  auto_threshold: 60\n":       {"flat", 60},
		"mcp:\n  auto_threshold: 25\n":                     {"flat", 25},
		"mcp: {}\n":                                        {"flat", 40},
		"mcp:\n  mode: progressive\n  auto_threshold: 7\n": {"progressive", 7},
	} {
		cfg, err := decodeConfig(strings.NewReader(yaml))
		if err != nil || cfg.MCP.Mode != want.mode || !cfg.MCP.AutoThreshold.set || cfg.MCP.AutoThreshold.value != want.threshold {
			t.Fatalf("%q config=%+v error=%v", yaml, cfg.MCP, err)
		}
	}
	for name, yaml := range map[string]string{
		"explicit zero":           "mcp:\n  auto_threshold: 0\n",
		"zero in auto mode":       "mcp:\n  mode: auto\n  auto_threshold: 0\n",
		"negative":                "mcp:\n  mode: auto\n  auto_threshold: -1\n",
		"over limit":              "mcp:\n  auto_threshold: 1001\n",
		"over limit, progressive": "mcp:\n  mode: progressive\n  auto_threshold: 5000\n",
		"null threshold":          "mcp:\n  auto_threshold: null\n",
		"tilde null threshold":    "mcp:\n  auto_threshold: ~\n",
		"empty threshold":         "mcp:\n  auto_threshold:\n",
		"float threshold":         "mcp:\n  auto_threshold: 1.5\n",
		"float whole threshold":   "mcp:\n  auto_threshold: 10.0\n",
		"string threshold":        "mcp:\n  auto_threshold: forty\n",
		"unknown mode":            "mcp:\n  mode: lazy\n",
		"uppercase mode":          "mcp:\n  mode: Flat\n",
		"empty mode":              "mcp:\n  mode: \"\"\n",
		"unknown key":             "mcp:\n  mode: flat\n  page_size: 10\n",
		"unknown root":            "mcps:\n  mode: flat\n",
	} {
		if _, err := decodeConfig(strings.NewReader(yaml)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

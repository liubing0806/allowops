package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJoinTokenSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("  fixture-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		args    []string
		stdin   string
		want    string
		invalid bool
	}{
		{"legacy", []string{"--token", "fixture-token"}, "", "fixture-token", false},
		{"file", []string{"--token-file", path}, "", "fixture-token", false},
		{"stdin", []string{"--token-stdin"}, " fixture-token\n", "fixture-token", false},
		{"missing", nil, "", "", true},
		{"conflict", []string{"--token", "fixture-token", "--token-file", path}, "", "", true},
		{"empty", []string{"--token-stdin"}, " \n", "", true},
		{"large", []string{"--token-stdin"}, strings.Repeat("x", 4097), "", true},
		{"boundary", []string{"--token-stdin"}, strings.Repeat("x", 4096), strings.Repeat("x", 4096), false},
		{"missing-file", []string{"--token-file", path + "-missing"}, "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := newCommand()
			join, _, err := root.Find([]string{"join"})
			if err != nil {
				t.Fatal(err)
			}
			join.SetIn(strings.NewReader(tc.stdin))
			if err := join.ParseFlags(tc.args); err != nil {
				t.Fatal(err)
			}
			got, err := readJoinToken(join)
			if (err != nil) != tc.invalid || got != tc.want {
				t.Fatalf("token source result matches=%t error=%v invalid=%t", got == tc.want, err, tc.invalid)
			}
			if err != nil && strings.Contains(err.Error(), "fixture-token") {
				t.Fatal("token leaked in error")
			}
		})
	}
}

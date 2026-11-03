package jvmtarget

import (
	"strings"
	"testing"
)

func TestTargetValidate(t *testing.T) {
	valid := []Target{
		{Name: "api", SystemdUnit: "api.service"},
		{Name: "api", SystemdUnit: "my-app@prod_1.service"},
		{Name: "web.1", Container: "shop-web_1", MainClass: "com.example.shop.Application"},
		{Name: "jar", Container: "web", MainClass: "/opt/app/app.jar"},
		{Name: "id", Container: strings.Repeat("a", 64), MainClass: "Main"},
	}
	for _, target := range valid {
		if err := target.Validate(); err != nil {
			t.Errorf("%+v: %v", target, err)
		}
	}
	long := strings.Repeat("a", 200)
	invalid := []struct {
		name string
		t    Target
	}{
		{"empty target", Target{Name: "x"}},
		{"unit and container", Target{Name: "x", SystemdUnit: "a.service", Container: "web", MainClass: "Main"}},
		{"unit and main class", Target{Name: "x", SystemdUnit: "a.service", MainClass: "Main"}},
		{"container without main class", Target{Name: "x", Container: "web"}},
		{"main class without container", Target{Name: "x", MainClass: "Main"}},
		{"unit that is not a service", Target{Name: "x", SystemdUnit: "a.timer"}},
		{"unit without suffix", Target{Name: "x", SystemdUnit: "api"}},
		{"unit that is an option", Target{Name: "x", SystemdUnit: "--user.service"}},
		{"unit with a space", Target{Name: "x", SystemdUnit: "a b.service"}},
		{"unit with a slash", Target{Name: "x", SystemdUnit: "../a.service"}},
		{"unit with a newline", Target{Name: "x", SystemdUnit: "a\n.service"}},
		{"unit too long", Target{Name: "x", SystemdUnit: long + ".service"}},
		{"container that is an option", Target{Name: "x", Container: "-v", MainClass: "Main"}},
		{"container with a slash", Target{Name: "x", Container: "a/b", MainClass: "Main"}},
		{"container with a path escape", Target{Name: "x", Container: "..", MainClass: "Main"}},
		{"container with a space", Target{Name: "x", Container: "a b", MainClass: "Main"}},
		{"container with a query", Target{Name: "x", Container: "web?all=1", MainClass: "Main"}},
		{"container too long", Target{Name: "x", Container: strings.Repeat("a", 129), MainClass: "Main"}},
		{"main class with a space", Target{Name: "x", Container: "web", MainClass: "Main arg"}},
		{"main class with a newline", Target{Name: "x", Container: "web", MainClass: "Main\narg"}},
		{"main class with NUL", Target{Name: "x", Container: "web", MainClass: "Main\x00"}},
		{"main class too long", Target{Name: "x", Container: "web", MainClass: strings.Repeat("a", 513)}},
		{"name with a space", Target{Name: "a b", SystemdUnit: "a.service"}},
		{"name starting with a dash", Target{Name: "-a", SystemdUnit: "a.service"}},
		{"empty name", Target{SystemdUnit: "a.service"}},
		{"name too long", Target{Name: strings.Repeat("a", 65), SystemdUnit: "a.service"}},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.t.Validate(); err == nil {
				t.Errorf("%+v accepted", tc.t)
			}
		})
	}
}

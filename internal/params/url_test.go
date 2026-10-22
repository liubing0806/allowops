package params

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func urlDefinitions(t *testing.T) map[string]Definition {
	t.Helper()
	var defs map[string]Definition
	if err := json.Unmarshal([]byte(`{"url":{"type":"url","description":"url","allowed_prefixes":["https://example.com/api"]}}`), &defs); err != nil {
		t.Fatal(err)
	}
	return defs
}

func TestURLParameter(t *testing.T) {
	defs := urlDefinitions(t)
	for _, value := range []string{"https://example.com/api", "https://EXAMPLE.com:443/api/items?q=x", "https://example.com/api/a%20b"} {
		if _, err := Parse(defs, map[string]any{"url": value}); err != nil {
			t.Errorf("%q: %v", value, err)
		}
	}
	for _, value := range []string{"https://example.com/apix", "http://example.com/api", "https://example.com:444/api", "https://evil.com/api", "https://user:pass@example.com/api", "https://example.com/api/../secret", "https://example.com/api/%2e%2e/secret", "https://example.com/api/%252e%252e/secret", "https://example.com/api%2fsecret", "https://example.com/api\\secret", "https://example.com/api/%5csecret"} {
		if _, err := Parse(defs, map[string]any{"url": value}); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
}

func TestURLSchemaAndPrefixValidation(t *testing.T) {
	defs := urlDefinitions(t)
	schema, err := JSONSchema(defs)
	if err != nil {
		t.Fatal(err)
	}
	property := schema["properties"].(map[string]any)["url"].(map[string]any)
	if property["format"] != "uri" {
		t.Fatal(property)
	}
	for _, prefixes := range [][]string{nil, {"https://example.com/api?x=y"}, {"https://example.com/%2fapi"}, {"ftp://example.com/api"}} {
		d := defs["url"]
		d.AllowedPrefixes = prefixes
		defs["url"] = d
		if err := ValidateDefinitions(defs); err == nil {
			t.Fatalf("accepted prefixes %q", prefixes)
		}
	}
}

func FuzzURL(f *testing.F) {
	for _, seed := range []string{"https://example.com/api", "https://example.com/api/%2e%2e", "https://user@example.com/api", "https://example.com/api?q=a", "https://[::1]/api"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		u, err := ParseURL(value, []string{"https://example.com/api"})
		if err != nil {
			return
		}
		if u.Scheme != "https" || u.User != nil || !sameOrigin(u, mustURL(t, "https://example.com")) || (u.Path != "/api" && !strings.HasPrefix(u.Path, "/api/")) {
			t.Fatalf("accepted unsafe URL %q: %#v", value, u)
		}
	})
}
func mustURL(t *testing.T, value string) *url.URL {
	t.Helper()
	u, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestURLNormalization(t *testing.T) {
	for _, tc := range []struct{ raw, prefix, want string }{
		{"https://EXAMPLE.com:443/api?q=x", "https://example.com/api", "https://example.com/api?q=x"},
		{"http://EXAMPLE.com:80/api", "http://example.com/api", "http://example.com/api"},
		{"http://[ABCD::1]:80/api", "http://[abcd::1]/api", "http://[abcd::1]/api"},
		{"https://EXAMPLE.com:8443/api", "https://example.com:8443/api", "https://example.com:8443/api"},
	} {
		u, err := ParseURL(tc.raw, []string{tc.prefix})
		if err != nil || u.String() != tc.want {
			t.Errorf("%q => %v %v; want %q", tc.raw, u, err, tc.want)
		}
	}
}

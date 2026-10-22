package catalog

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/params"
)

func TestReaderFutureConstrainedSignedCatalog(t *testing.T) {
	min := int64(1)
	for _, tc := range []struct {
		name string
		def  params.Definition
	}{
		{"default", params.Definition{Default: "future-default"}},
		{"max_len", params.Definition{MaxLen: 10}},
		{"regex", params.Definition{Regex: `^[a-z]+$`}},
		{"bounds", params.Definition{Min: &min, Max: 2.5}},
		{"array", params.Definition{MaxItems: 3, Values: []string{"x", "y"}}},
		{"paths", params.Definition{AllowedRoots: []string{"/tmp"}, AllowedPrefixes: []string{"https://example.invalid/"}, Format: "future_format"}},
		{"combined", params.Definition{Default: map[string]any{"future": true}, MaxLen: 10, MaxItems: 2, Regex: `^x+$`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			known := Action{Name: "known", Description: "known", Risk: "read", Exec: []any{"/usr/bin/printf", "ok"}, Timeout: "1s", MaxOutput: 1024}
			future := known
			future.Name = "future"
			d := tc.def
			d.Type, d.Description = "future_type", "future parameter"
			future.Params = map[string]params.Definition{"value": d}
			future.Exec = []any{"/usr/bin/printf", "{value}"}
			p, err := Build(&Catalog{Config: Config{SchemaVersion: 1, CatalogID: "future_constraints"}, Actions: map[string]Action{known.Name: known}}, BuildOptions{Now: time.Now(), TTL: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			p.Actions[future.Name] = future
			p.Digests[future.Name], err = ActionDigest(future)
			if err != nil {
				t.Fatal(err)
			}
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := CanonicalJSON(p)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := Sign(payload, SigningKey{PrivateKey: private})
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := Verify(envelope, map[string]ed25519.PublicKey{KeyID(public): public}, VerifyOptions{})
			if err != nil {
				t.Fatalf("reader rejected mixed signed catalog for %s; want per-action unsupported", tc.name)
			}
			if !CheckHost(loaded.Actions["known"]).Supported || CheckHost(loaded.Actions["future"]).Supported {
				t.Error("mixed support decision changed")
			}
			if _, err := ValidateAction(future); err == nil {
				t.Error("authoring accepted future type")
			}
			if _, err := params.Parse(future.Params, map[string]any{"value": "x"}); err == nil {
				t.Error("execution parameter parser accepted future type")
			}
			if _, err := params.ParseGateway(future.Params, map[string]any{"value": "x"}); err == nil {
				t.Error("gateway parameter parser accepted future type")
			}
		})
	}
}

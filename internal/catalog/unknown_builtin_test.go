package catalog

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestVerifyUnknownBuiltinOnlyDisablesAction(t *testing.T) {
	known := Action{Name: "known", Description: "known", Risk: "read", Exec: []any{"/usr/bin/printf", "ok"}, Timeout: "1s", MaxOutput: 1024}
	unknown := Action{Name: "unknown", Description: "future handler", Risk: "read", Builtin: "future_handler", BuiltinConfig: map[string]any{"future": true}, Timeout: "1s", MaxOutput: 1024}
	p, err := Build(&Catalog{Config: Config{SchemaVersion: 1, CatalogID: "mixed"}, Actions: map[string]Action{known.Name: known}}, BuildOptions{Now: time.Now(), TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	p.Actions[unknown.Name] = unknown
	p.Digests[unknown.Name], err = ActionDigest(unknown)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verify := func() (*Package, error) {
		payload, err := CanonicalJSON(p)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := Sign(payload, SigningKey{PrivateKey: private})
		if err != nil {
			t.Fatal(err)
		}
		return Verify(envelope, map[string]ed25519.PublicKey{KeyID(public): public}, VerifyOptions{})
	}
	loaded, err := verify()
	if err != nil {
		t.Fatalf("known schema mixed catalog rejected: %v", err)
	}
	if !CheckHost(loaded.Actions[known.Name]).Supported || CheckHost(loaded.Actions[unknown.Name]).Supported {
		t.Fatal("support must be decided per action")
	}
	if _, err := ValidateAction(unknown); err == nil {
		t.Fatal("authoring must reject unknown handlers")
	}
	p.SchemaVersion = 999
	if _, err := verify(); err == nil {
		t.Fatal("unknown schema accepted")
	}
	p.SchemaVersion = 1
	unknown.Exec = []any{"/usr/bin/printf", "unsafe mixed modes"}
	p.Actions[unknown.Name] = unknown
	p.Digests[unknown.Name], _ = ActionDigest(unknown)
	if _, err := verify(); err == nil {
		t.Fatal("unknown handler bypassed common action validation")
	}
}

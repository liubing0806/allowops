package catalogsvc

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/catalog"
)

// signedEnvelope signs a package holding one action with the given name. The
// digest is computed directly, without Build, so the name may be one that was
// reserved after an older CLI signed the package.
func signedEnvelope(t *testing.T, key ed25519.PrivateKey, name string) []byte {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	a := catalog.Action{Name: name, Description: "fixture", Risk: "read", Exec: []any{"/usr/bin/true"}, Timeout: "1s", MaxOutput: 1024}
	digest, err := catalog.ActionDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	p := &catalog.Package{SchemaVersion: 1, CatalogID: "test", Version: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour), Actions: map[string]catalog.Action{name: a}, Digests: map[string]string{name: digest}}
	payload, err := catalog.CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	e, err := catalog.Sign(payload, catalog.SigningKey{PrivateKey: key})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Publish refuses the progressive disclosure meta-tool names before it touches
// the store, while Verify, which also reads stored versions, still accepts them.
func TestPublishRejectsProgressiveReservedNames(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := key.Public().(ed25519.PublicKey)
	s := &Service{Trusted: map[string]ed25519.PublicKey{catalog.KeyID(public): public}, MaxEnvelopeBytes: 1 << 20, MaxActionBytes: 64 << 10}
	for _, name := range []string{"actions_search", "actions_invoke_read", "actions_invoke_write", "actions_invoke_dangerous"} {
		raw := signedEnvelope(t, key, name)
		if _, err := s.Verify(raw); err != nil {
			t.Fatalf("Verify %s: %v", name, err)
		}
		if _, err := s.Publish(context.Background(), raw); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("Publish %s: error=%v", name, err)
		}
	}
}

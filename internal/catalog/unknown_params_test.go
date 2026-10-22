package catalog

import (
	"crypto/ed25519"
	"crypto/rand"
	"maps"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/params"
)

func TestVerifyFutureParameterOnlyDisablesAction(t *testing.T) {
	known := Action{Name: "known", Description: "known", Risk: "read", Exec: []any{"/usr/bin/printf", "ok"}, Timeout: "1s", MaxOutput: 1024}
	future := known
	future.Name = "future"
	future.Params = map[string]params.Definition{"value": {Type: "future_type", Description: "future value"}}
	future.Exec = []any{"/usr/bin/printf", "{value}"}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(a Action, mutate func(*Package)) (*Package, error) {
		p, e := Build(&Catalog{Config: Config{SchemaVersion: 1, CatalogID: "future"}, Actions: map[string]Action{known.Name: known}}, BuildOptions{Now: time.Now(), TTL: time.Hour})
		if e != nil {
			t.Fatal(e)
		}
		p.Actions[a.Name] = a
		p.Digests[a.Name], e = ActionDigest(a)
		if e != nil {
			t.Fatal(e)
		}
		if mutate != nil {
			mutate(p)
		}
		data, e := CanonicalJSON(p)
		if e != nil {
			t.Fatal(e)
		}
		envelope, e := Sign(data, SigningKey{PrivateKey: priv})
		if e != nil {
			t.Fatal(e)
		}
		return Verify(envelope, map[string]ed25519.PublicKey{KeyID(pub): pub}, VerifyOptions{})
	}
	loaded, err := verify(future, nil)
	if err != nil {
		t.Errorf("known schema mixed signed catalog rejected: %v; want per-action unsupported", err)
	} else if !CheckHost(loaded.Actions["known"]).Supported || CheckHost(loaded.Actions["future"]).Supported {
		t.Error("support must be decided per action")
	}
	if _, err := ValidateAction(future); err == nil {
		t.Error("authoring accepted future parameter")
	}
	if _, err := Build(&Catalog{Config: Config{SchemaVersion: 1, CatalogID: "strict"}, Actions: map[string]Action{future.Name: future}}, BuildOptions{}); err == nil {
		t.Error("Build accepted future parameter")
	}
	for name, change := range map[string]func(*Action){
		"empty-type":          func(a *Action) { a.Params["value"] = params.Definition{Description: "value"} },
		"invalid-type":        func(a *Action) { a.Params["value"] = params.Definition{Type: "bad\ntype", Description: "value"} },
		"invalid-name":        func(a *Action) { a.Params["BadName"] = params.Definition{Type: "future_type", Description: "value"} },
		"missing-description": func(a *Action) { a.Params["value"] = params.Definition{Type: "future_type"} },
		"wrong-constraint": func(a *Action) {
			a.Params["value"] = params.Definition{Type: "future_type", Description: "value", MaxLen: -1}
		},
		"bad-known-definition": func(a *Action) { a.Params["other"] = params.Definition{Type: params.Enum, Description: "enum"} },
		"mixed-modes":          func(a *Action) { a.Builtin = "future_builtin" },
		"invalid-action":       func(a *Action) { a.Timeout = "-1s" },
		"dynamic-executable":   func(a *Action) { a.Exec[0] = "{value}" },
	} {
		t.Run(name, func(t *testing.T) {
			a := future
			a.Params = maps.Clone(future.Params)
			a.Exec = append([]any{}, future.Exec...)
			change(&a)
			if _, err := verify(a, nil); err == nil {
				t.Error("malformed action accepted alongside future type")
			}
		})
	}
	for name, mutate := range map[string]func(*Package){
		"schema": func(p *Package) { p.SchemaVersion = 999 },
		"digest": func(p *Package) { p.Digests[future.Name] = "wrong" },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verify(future, mutate); err == nil {
				t.Error("unsafe package accepted")
			}
		})
	}
}

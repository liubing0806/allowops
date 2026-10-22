package catalog

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validAction = "name: echo_value\ndescription: Echo value\nrisk: read\nparams:\n  value: {type: string, max_len: 128, description: value}\nexec: [/bin/echo, '{value}']\ntimeout: 1s\nmax_output: 1KB\n"

func TestLoadAndBuild(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "actions"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "catalog.yaml"), []byte("catalog_id: test\nschema_version: 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "actions", "echo_value.yaml"), []byte(validAction), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 13, 1, 2, 3, 0, time.UTC)
	p, err := Build(c, BuildOptions{Now: now, GitCommit: "ae79ac7"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 20261013010203 || !p.ExpiresAt.Equal(now.Add(90*24*time.Hour)) {
		t.Fatal(p)
	}
	a := p.Actions["echo_value"]
	digest, err := ActionDigest(a)
	if err != nil || digest != p.Digests["echo_value"] {
		t.Fatalf("%s %v", digest, err)
	}
	x, _ := CanonicalJSON(p)
	y, _ := CanonicalJSON(p)
	if string(x) != string(y) {
		t.Fatal("unstable JSON")
	}
}

// Security 8: relative executables and interpreters are rejected; safe wrappers are allowed.
func TestSecurity8Validation(t *testing.T) {
	for _, program := range []string{"echo", "/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash", "/bin/ash", "/usr/bin/python3", "/usr/bin/perl", "/usr/bin/ruby", "/usr/bin/node", "/usr/bin/php", "/usr/bin/lua", "/usr/bin/awk", "/usr/bin/gawk", "/usr/bin/mawk", "/usr/bin/sed"} {
		a, _ := ParseAction([]byte(validAction))
		a.Exec = []any{program}
		if _, err := ValidateAction(a); err == nil {
			t.Fatalf("accepted %s", program)
		}
	}
	for _, argv := range [][]any{
		{"/usr/bin/docker", "exec", "container", "echo"}, {"/usr/bin/kubectl", "exec", "pod", "--", "echo"},
		{"/usr/bin/nsenter", "echo"}, {"/usr/bin/chroot", "/", "echo"}, {"/usr/bin/env", "echo"},
		{"/usr/bin/timeout", "1", "echo"}, {"/usr/bin/nice", "echo"}, {"/usr/bin/ionice", "echo"},
		{"/usr/bin/stdbuf", "-oL", "echo"}, {"/usr/bin/xargs", "echo"},
	} {
		a, _ := ParseAction([]byte(validAction))
		a.Exec = argv
		a.AllowInterpreter = true
		if _, err := ValidateAction(a); err != nil {
			t.Fatalf("%q: %v", argv, err)
		}
	}
	a, _ := ParseAction([]byte(validAction))
	a.Exec = []any{"/usr/bin/docker", "ps"}
	if _, err := ValidateAction(a); err != nil {
		t.Fatal(err)
	}
	a.Exec = []any{"/bin/bash"}
	a.AllowInterpreter = true
	if warnings, err := ValidateAction(a); err != nil || len(warnings) == 0 {
		t.Fatalf("%v %v", warnings, err)
	}
	a.Exec = []any{"/bin/echo", "sudo"}
	if _, err := ValidateAction(a); err == nil {
		t.Fatal("accepted sudo")
	}
}

func TestUnsupportedFeaturesAndStrictYAML(t *testing.T) {
	for _, feature := range []string{"steps: []", "script: {file: x, interpreter: /bin/sh}", "builtin: unknown_handler", "filters: [unknown]", "exec_fallbacks: [relative]"} {
		a, err := ParseAction([]byte(validAction + feature + "\n"))
		if err == nil {
			_, err = ValidateAction(a)
		}
		if err == nil {
			t.Fatalf("%s: %v", feature, err)
		}
	}
	for _, data := range []string{validAction + "typo: true\n", validAction + "name: duplicate\n", validAction + "---\nname: hidden\n"} {
		if _, err := ParseAction([]byte(data)); err == nil {
			t.Fatal("accepted ambiguous YAML")
		}
	}
	for _, name := range []string{"hosts_search", "jobs_get", "jobs_list", "jobs_cancel", "Bad-name"} {
		a, _ := ParseAction([]byte(validAction))
		a.Name = name
		if _, err := ValidateAction(a); err == nil {
			t.Fatal(name)
		}
	}
}

// Security 8: host inspection rejects shebang scripts and missing executables.
func TestSecurity8HostCheck(t *testing.T) {
	a, _ := ParseAction([]byte(validAction))
	if status := CheckHost(a); !status.Supported {
		t.Fatal(status)
	}
	a.Exec[0] = filepath.Join(t.TempDir(), "missing")
	if status := CheckHost(a); status.Supported || status.Status != "unsupported" {
		t.Fatal(status)
	}
	script := filepath.Join(t.TempDir(), "wrapper")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	a.Exec[0] = script
	if CheckHost(a).Supported {
		t.Fatal("accepted shebang")
	}
	a.AllowInterpreter = true
	if s := CheckHost(a); !s.Supported || len(s.Warnings) == 0 {
		t.Fatal(s)
	}
	for _, target := range []string{"/bin/sh"} {
		alias := filepath.Join(t.TempDir(), "alias")
		if err := os.Symlink(target, alias); err != nil {
			t.Fatal(err)
		}
		a.Exec = []any{alias, "echo"}
		a.AllowInterpreter = false
		if status := CheckHost(a); status.Supported {
			t.Fatalf("accepted alias to %s", target)
		}
	}
}

func TestDSSEPayloadValidation(t *testing.T) {
	e, keys, now := signedPackage(t)
	raw, _ := base64.StdEncoding.DecodeString(e.Payload)
	p, err := ParsePackage(raw)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	trusted := map[string]ed25519.PublicKey{"test": public}
	p.Actions["echo_value"] = func() Action { a := p.Actions["echo_value"]; a.Description = "changed"; return a }()
	data, _ := CanonicalJSON(p)
	bad, _ := Sign(data, SigningKey{KeyID: "test", PrivateKey: private})
	if _, err := Verify(bad, trusted, VerifyOptions{Now: now}); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("%v", err)
	}
	noncanonical, _ := Sign(append(raw, '\n'), SigningKey{KeyID: "test", PrivateKey: private})
	if _, err := Verify(noncanonical, trusted, VerifyOptions{Now: now}); err == nil {
		t.Fatal("accepted noncanonical payload")
	}
	e.Signatures = append([]Signature{{KeyID: "old", Sig: "broken"}}, e.Signatures...)
	if _, err := Verify(e, keys, VerifyOptions{Now: now}); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`null`, `{"payloadType":"x","payloadType":"y"}`, `{"payloadType":"x","extra":true}`, `{} {}`} {
		if _, err := ParseEnvelope([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func signedPackage(t *testing.T) (*Envelope, map[string]ed25519.PublicKey, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 13, 1, 0, 0, 0, time.UTC)
	a, _ := ParseAction([]byte(validAction))
	p, err := Build(&Catalog{Config: Config{CatalogID: "test", SchemaVersion: 1}, Actions: map[string]Action{a.Name: a}}, BuildOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := CanonicalJSON(p)
	e, err := Sign(payload, SigningKey{KeyID: "old", PrivateKey: key})
	if err != nil {
		t.Fatal(err)
	}
	return e, map[string]ed25519.PublicKey{"old": pub}, now
}

// T4 and T11: tampering, key rotation, expiry, rollback, unsigned envelopes and clock skew.
func TestDSSETrustExpiryRollback(t *testing.T) {
	e, keys, now := signedPackage(t)
	if _, err := Verify(e, keys, VerifyOptions{Now: now, HighestVersion: 20261013010000}); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Envelope){
		func(e *Envelope) { e.Payload = base64.StdEncoding.EncodeToString([]byte(`{}`)) },
		func(e *Envelope) { e.PayloadType = "wrong" }, func(e *Envelope) { e.Signatures = nil },
		func(e *Envelope) { e.Signatures[0].Sig = "bad" },
	} {
		data, _ := json.Marshal(e)
		var bad Envelope
		_ = json.Unmarshal(data, &bad)
		mutate(&bad)
		if _, err := Verify(&bad, keys, VerifyOptions{Now: now}); err == nil {
			t.Fatal("accepted forged envelope")
		}
	}
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Verify(e, map[string]ed25519.PublicKey{"old": wrong}, VerifyOptions{Now: now}); err == nil {
		t.Fatal("accepted wrong key")
	}
	if _, err := Verify(e, keys, VerifyOptions{Now: now, HighestVersion: 20261013010001}); err == nil {
		t.Fatal("accepted rollback")
	}
	if _, err := Verify(e, keys, VerifyOptions{Now: now.Add(90*24*time.Hour + 5*time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(e, keys, VerifyOptions{Now: now.Add(90*24*time.Hour + 5*time.Minute + time.Nanosecond)}); err == nil {
		t.Fatal("accepted expiry")
	}
	if _, err := Verify(e, keys, VerifyOptions{Now: now.Add(-5*time.Minute - time.Nanosecond)}); err == nil {
		t.Fatal("accepted future package")
	}
	pub, newKey, _ := ed25519.GenerateKey(rand.Reader)
	if err := AddSignature(e, SigningKey{KeyID: "new", PrivateKey: newKey}); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(e, map[string]ed25519.PublicKey{"new": pub}, VerifyOptions{Now: now}); err != nil {
		t.Fatal(err)
	}
	if string(PAE("test", []byte("abc"))) != "DSSEv1 4 test 3 abc" {
		t.Fatal("wrong PAE")
	}
}

func FuzzLoadYAML(f *testing.F) {
	for _, seed := range []string{validAction, "catalog_id: test\nschema_version: 1\ndefaults: {max_output: 1KB, timeout: 1s}", "{}", "exec: [1]", "name: x\nname: y\n", "steps: []"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, err := ParseAction([]byte(s))
		if err == nil {
			_, _ = ValidateAction(a)
		}
		var config Config
		if decodeYAML([]byte(s), &config) == nil {
			_ = validateConfig(config)
		}
	})
}

func FuzzParseDSSE(f *testing.F) {
	a, _ := ParseAction([]byte(validAction))
	p, err := Build(&Catalog{Config: Config{CatalogID: "fuzz", SchemaVersion: 1}, Actions: map[string]Action{a.Name: a}}, BuildOptions{Now: time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		f.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := key.Public().(ed25519.PublicKey)
	payload, _ := CanonicalJSON(p)
	e, err := Sign(payload, SigningKey{KeyID: "fuzz", PrivateKey: key})
	if err != nil {
		f.Fatal(err)
	}
	seed, _ := json.Marshal(e)
	f.Add(string(seed))
	f.Add(`{"payloadType":"x","payload":"","signatures":[]}`)
	f.Add(`{}`)
	f.Add(`null`)
	f.Add(`[]`)
	f.Fuzz(func(t *testing.T, s string) {
		e, err := ParseEnvelope([]byte(s))
		if err == nil {
			_, _ = Verify(e, map[string]ed25519.PublicKey{"fuzz": pub}, VerifyOptions{Now: p.CreatedAt})
		}
	})
}

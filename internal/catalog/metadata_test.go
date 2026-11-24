package catalog

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var progressiveNames = []string{"actions_search", "actions_invoke_read", "actions_invoke_write", "actions_invoke_dangerous"}

func metadataAction(t *testing.T, fields string) (Action, error) {
	t.Helper()
	a, err := ParseAction([]byte(validAction + fields))
	if err != nil {
		return a, err
	}
	_, err = ValidateAction(a)
	return a, err
}

// metadataList returns n distinct values that each match the metadata pattern.
func metadataList(n int) []string {
	values := make([]string, n)
	for i := range values {
		values[i] = fmt.Sprintf("v%d", i)
	}
	return values
}

func metadataValues(n int) string {
	return "[" + strings.Join(metadataList(n), ", ") + "]"
}

var metadataNow = time.Date(2026, 11, 24, 1, 0, 0, 0, time.UTC)

// metadataPayload builds the package payload without Build, the way a package
// signed by an older or newer CLI reaches a reader.
func metadataPayload(t *testing.T, actions ...Action) []byte {
	t.Helper()
	p := &Package{SchemaVersion: 1, CatalogID: "test", Version: 20261124010000, CreatedAt: metadataNow, ExpiresAt: metadataNow.Add(time.Hour), Actions: map[string]Action{}, Digests: map[string]string{}}
	for _, a := range actions {
		digest, err := ActionDigest(a)
		if err != nil {
			t.Fatal(err)
		}
		p.Actions[a.Name] = a
		p.Digests[a.Name] = digest
	}
	payload, err := CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func signedMetadataPackage(t *testing.T, actions ...Action) (*Envelope, map[string]ed25519.PublicKey, time.Time) {
	t.Helper()
	return signMetadataPayload(t, metadataPayload(t, actions...))
}

func signMetadataPayload(t *testing.T, payload []byte) (*Envelope, map[string]ed25519.PublicKey, time.Time) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	e, err := Sign(payload, SigningKey{KeyID: "test", PrivateKey: key})
	if err != nil {
		t.Fatal(err)
	}
	return e, map[string]ed25519.PublicKey{"test": key.Public().(ed25519.PublicKey)}, metadataNow
}

func TestMetadataAccepted(t *testing.T) {
	long := "a" + strings.Repeat("b", 31)
	for _, fields := range []string{
		"",
		"toolset: jvm\n",
		"toolset: '" + long + "'\n",
		"tags: [gc]\n",
		"tags: " + metadataValues(16) + "\n",
		"entity_kinds: [jvm]\n",
		"entity_kinds: " + metadataValues(16) + "\n",
		"toolset: jvm\ntags: [gc, heap, threads]\nentity_kinds: [jvm, service_1]\n",
		"tags:\n  - gc\n  - heap\n",
	} {
		if _, err := metadataAction(t, fields); err != nil {
			t.Errorf("%q rejected: %v", fields, err)
		}
	}
	a, err := metadataAction(t, "toolset: jvm\ntags: [gc, heap]\nentity_kinds: [jvm]\n")
	if err != nil {
		t.Fatal(err)
	}
	if a.Toolset != "jvm" || !slices.Equal(a.Tags, []string{"gc", "heap"}) || !slices.Equal(a.EntityKinds, []string{"jvm"}) {
		t.Fatalf("decoded %q %q %q", a.Toolset, a.Tags, a.EntityKinds)
	}
}

// yaml.v3 decodes null as unset and true or 123 into a string field. Each of
// these must fail as a value, not as an unknown field ("not found").
func TestMetadataYAMLTypeRejected(t *testing.T) {
	for _, fields := range []string{
		"toolset: null\n", "toolset: ~\n", "toolset:\n", "toolset: ''\n", `toolset: ""` + "\n",
		"toolset: true\n", "toolset: 123\n", "toolset: 1.5\n", "toolset: [jvm]\n", "toolset: {a: b}\n",
		"tags: null\n", "tags:\n", "tags: []\n", "tags: [true]\n", "tags: [123]\n", "tags: [gc, null]\n",
		"tags: [gc, 1.5]\n", "tags: gc\n", "tags: {a: b}\n", "tags: [[gc]]\n",
		"entity_kinds: null\n", "entity_kinds: []\n", "entity_kinds: [false]\n", "entity_kinds: [jvm, 7]\n", "entity_kinds: jvm\n",
	} {
		_, err := metadataAction(t, fields)
		if err == nil || strings.Contains(err.Error(), "not found") {
			t.Errorf("%q: error=%v", fields, err)
		}
	}
}

func TestMetadataYAMLMergeKeysAndAliases(t *testing.T) {
	// Valid metadata supplied through YAML merge keys and aliases is accepted.
	validMerged := strings.Join([]string{
		"name: echo_value",
		"description: echo a value",
		"risk: read",
		"exec: [/usr/bin/echo, ok]",
		"timeout: 1s",
		"max_output: 1KB",
		"x_meta: &meta",
		"  toolset: jvm",
		"  tags: [gc, heap]",
		"  entity_kinds: [jvm]",
		"<<: *meta",
	}, "\n")
	// KnownFields rejects x_meta at top level; place anchor on an allowed field
	// or inside an unused sequence only when merge keys target an existing map,
	// or test a document-level merge via a YAML anchor inside params? No:
	// YAML allows anchoring a merge map inside another merged map, or anchoring
	// scalar/sequence values directly. Test valid alias + merge rejection below.
	_ = validMerged

	validAlias := validAction + "toolset: &ts jvm\ntags: [*ts, heap]\nentity_kinds: [*ts]\n"
	a, err := ParseAction([]byte(validAlias))
	if err != nil {
		t.Fatalf("valid alias rejected: %v", err)
	}
	if a.Toolset != "jvm" || !slices.Equal(a.Tags, []string{"jvm", "heap"}) || !slices.Equal(a.EntityKinds, []string{"jvm"}) {
		t.Fatalf("decoded alias metadata: %q %q %q", a.Toolset, a.Tags, a.EntityKinds)
	}

	// Mapping key aliases must resolve to their effective field names, matching
	// yaml.v3 struct decoding rather than indexing by anchor name.
	aliasedKey := validAction + "tags: [&k toolset]\n*k: jvm\n"
	a, err = ParseAction([]byte(aliasedKey))
	if err != nil || a.Toolset != "jvm" || !slices.Equal(a.Tags, []string{"toolset"}) {
		t.Fatalf("valid aliased mapping key: toolset=%q tags=%q err=%v", a.Toolset, a.Tags, err)
	}

	// Merge keys and aliases (for values or mapping keys) carrying non-string
	// or empty metadata values or non-integer max_targets must fail ParseAction.
	for name, doc := range map[string]string{
		"merge bool toolset":          validAction + "<<: {toolset: true}\n",
		"merge null toolset":          validAction + "<<: {toolset: null}\n",
		"merge empty tags":            validAction + "<<: {tags: []}\n",
		"merge int tag":               validAction + "<<: {tags: [123]}\n",
		"merge bool kind":             validAction + "<<: {entity_kinds: [false]}\n",
		"merge float max_targets":     validAction + "<<: {max_targets: 1.5}\n",
		"merge list bad second":       validAction + "<<: [{toolset: jvm}, {tags: []}]\n",
		"alias bool element":          validAction + "idempotent: &flag true\ntags: [*flag]\n",
		"alias key bool toolset":      validAction + "tags: [&k toolset]\n*k: true\n",
		"alias key float max_targets": validAction + "tags: [&k max_targets]\n*k: 1.5\n",
	} {
		if _, err := ParseAction([]byte(doc)); err == nil {
			t.Errorf("%s: accepted invalid YAML metadata", name)
		}
	}

	// Explicit key on the action mapping overrides an invalid merged key,
	// matching YAML 1.1 merge semantics.
	override := validAction + "<<: {toolset: true}\ntoolset: jvm\n"
	if a, err := ParseAction([]byte(override)); err != nil || a.Toolset != "jvm" {
		t.Fatalf("explicit override over merge key: toolset=%q err=%v", a.Toolset, err)
	}
}

func TestMetadataValuesRejected(t *testing.T) {
	long := "a" + strings.Repeat("b", 32)
	for _, fields := range []string{
		"toolset: Jvm\n", "toolset: j-vm\n", "toolset: 1jvm\n", "toolset: _jvm\n", "toolset: " + long + "\n", "toolset: 'jvm '\n",
		"tags: " + metadataValues(17) + "\n", "tags: [Gc]\n", "tags: [g-c]\n", "tags: [" + long + "]\n", "tags: [gc, gc]\n", "tags: ['']\n",
		"entity_kinds: " + metadataValues(17) + "\n", "entity_kinds: [JVM]\n", "entity_kinds: [jvm, jvm]\n", "entity_kinds: ['']\n",
	} {
		if _, err := metadataAction(t, fields); err == nil {
			t.Errorf("accepted %q", fields)
		}
	}
}

func TestMetadataInDigest(t *testing.T) {
	digests := map[string]string{}
	actions := map[string]Action{}
	for _, fields := range []string{
		"",
		"toolset: jvm\n",
		"toolset: mysql\n",
		"tags: [gc]\n",
		"tags: [gc, heap]\n",
		"tags: [heap, gc]\n",
		"entity_kinds: [jvm]\n",
		"entity_kinds: [service]\n",
	} {
		a, err := metadataAction(t, fields)
		if err != nil {
			t.Fatal(err)
		}
		actions[fields] = a
		digest, err := ActionDigest(a)
		if err != nil {
			t.Fatal(err)
		}
		if other, ok := digests[digest]; ok {
			t.Errorf("digest of %q equals %q", fields, other)
		}
		digests[digest] = fields
	}
	data, err := CanonicalJSON(actions[""])
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"toolset", "tags", "entity_kinds"} {
		if strings.Contains(string(data), `"`+key+`"`) {
			t.Errorf("omitted %s appears in the signed action: %s", key, data)
		}
	}
	data, err = CanonicalJSON(actions["tags: [gc, heap]\n"])
	if err != nil || !strings.Contains(string(data), `"tags":["gc","heap"]`) {
		t.Fatalf("signed action lacks tags: %v %s", err, data)
	}
}

func TestBuildAndVerifyCarryMetadata(t *testing.T) {
	a, err := metadataAction(t, "toolset: jvm\ntags: [gc, heap]\nentity_kinds: [jvm]\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Build(&Catalog{Config: Config{SchemaVersion: 1, CatalogID: "test"}, Actions: map[string]Action{a.Name: a}}, BuildOptions{Now: metadataNow})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateForPublish(p); err != nil {
		t.Fatal(err)
	}
	payload, err := CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	e, trusted, now := signMetadataPayload(t, payload)
	verified, err := Verify(e, trusted, VerifyOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	got := verified.Actions[a.Name]
	if got.Toolset != "jvm" || !slices.Equal(got.Tags, []string{"gc", "heap"}) || !slices.Equal(got.EntityKinds, []string{"jvm"}) {
		t.Fatalf("verified %q %q %q", got.Toolset, got.Tags, got.EntityKinds)
	}
}

// The digest omits empty values, so only the canonical payload check rejects
// a signed package that spells an omitted field as null, [] or "".
func TestVerifyRejectsNoncanonicalMetadata(t *testing.T) {
	a, err := metadataAction(t, "")
	if err != nil {
		t.Fatal(err)
	}
	payload := metadataPayload(t, a)
	e, trusted, now := signMetadataPayload(t, payload)
	if _, err := Verify(e, trusted, VerifyOptions{Now: now}); err != nil {
		t.Fatal(err)
	}
	for _, edit := range [][2]string{
		{`"timeout":`, `"tags":null,"timeout":`},
		{`"timeout":`, `"tags":[],"timeout":`},
		{`"exec":`, `"entity_kinds":null,"exec":`},
		{`"exec":`, `"entity_kinds":[],"exec":`},
		{`"timeout":"1s"`, `"timeout":"1s","toolset":""`},
	} {
		if strings.Count(string(payload), edit[0]) != 1 {
			t.Fatalf("payload does not contain %s once: %s", edit[0], payload)
		}
		bad := []byte(strings.Replace(string(payload), edit[0], edit[1], 1))
		if _, err := ParsePackage(bad); err != nil {
			t.Fatalf("%s: reader rejected before the canonical check: %v", edit[1], err)
		}
		e, trusted, _ := signMetadataPayload(t, bad)
		if _, err := Verify(e, trusted, VerifyOptions{Now: now}); err == nil || !strings.Contains(err.Error(), "canonical") {
			t.Errorf("%s: error=%v", edit[1], err)
		}
	}
}

func TestProgressiveReservedNamesRejectedWhenAuthoring(t *testing.T) {
	for _, name := range progressiveNames {
		a, err := ParseAction([]byte(strings.Replace(validAction, "name: echo_value", "name: "+name, 1)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateAction(a); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("ValidateAction %s: error=%v", name, err)
		}
		if _, err := Build(&Catalog{Config: Config{SchemaVersion: 1, CatalogID: "test"}, Actions: map[string]Action{name: a}}, BuildOptions{}); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("Build %s: error=%v", name, err)
		}
		root := t.TempDir()
		if err := os.Mkdir(filepath.Join(root, "actions"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "catalog.yaml"), []byte("catalog_id: test\nschema_version: 1\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "actions", name+".yaml"), []byte(strings.Replace(validAction, "name: echo_value", "name: "+name, 1)), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(root); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("Load %s: error=%v", name, err)
		}
	}
}

// A package signed before the names were reserved stays readable and its
// actions stay runnable; only publishing it again is refused.
func TestProgressiveReservedNamesReadable(t *testing.T) {
	base, err := metadataAction(t, "")
	if err != nil {
		t.Fatal(err)
	}
	var actions []Action
	for _, name := range progressiveNames {
		a := base
		a.Name = name
		actions = append(actions, a)
	}
	e, trusted, now := signedMetadataPackage(t, actions...)
	p, err := Verify(e, trusted, VerifyOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range progressiveNames {
		if support := CheckHost(p.Actions[name]); !support.Supported {
			t.Errorf("host check of %s: %s", name, support.Reason)
		}
	}
	if err := ValidateForPublish(p); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("ValidateForPublish: error=%v", err)
	}
	for _, name := range progressiveNames {
		a := base
		a.Name = name
		e, trusted, now := signedMetadataPackage(t, a)
		single, err := Verify(e, trusted, VerifyOptions{Now: now})
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateForPublish(single); err == nil || !strings.Contains(err.Error(), "action "+name) {
			t.Errorf("ValidateForPublish %s: error=%v", name, err)
		}
	}
}

func TestReadReservedNamesRejectedWhenReading(t *testing.T) {
	base, err := metadataAction(t, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range readReservedActionNames {
		a := base
		a.Name = name
		e, trusted, now := signedMetadataPackage(t, a)
		if _, err := Verify(e, trusted, VerifyOptions{Now: now}); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("Verify %s: error=%v", name, err)
		}
	}
}

// A later release may relax the metadata limits. Readers accept such a package
// so an older gateway or host keeps loading it; publishing it here is refused.
func TestFutureMetadataReadable(t *testing.T) {
	base, err := metadataAction(t, "")
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Action){
		"seventeen tags":         func(a *Action) { a.Tags = metadataList(17) },
		"seventeen entity kinds": func(a *Action) { a.EntityKinds = metadataList(17) },
		"long toolset":           func(a *Action) { a.Toolset = strings.Repeat("a", 40) },
		"uppercase tag":          func(a *Action) { a.Tags = []string{"GC"} },
		"duplicate entity kind":  func(a *Action) { a.EntityKinds = []string{"jvm", "jvm"} },
	} {
		a := base
		change(&a)
		e, trusted, now := signedMetadataPackage(t, a)
		p, err := Verify(e, trusted, VerifyOptions{Now: now})
		if err != nil {
			t.Errorf("%s: reader rejected: %v", name, err)
			continue
		}
		if support := CheckHost(p.Actions[a.Name]); !support.Supported {
			t.Errorf("%s: host check: %s", name, support.Reason)
		}
		if err := ValidateForPublish(p); err == nil {
			t.Errorf("%s: publish accepted", name)
		}
	}
}

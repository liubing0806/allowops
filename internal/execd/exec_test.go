package execd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/executor"
)

type fixture struct {
	cache Cache
	key   ed25519.PrivateKey
	now   time.Time
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	base := t.TempDir()
	cache := Cache{CatalogDir: filepath.Join(base, "catalogs"), KeysDir: filepath.Join(base, "keys"), StateDir: filepath.Join(base, "state"), StateOwner: os.Getuid(), KeyOwner: os.Getuid()}
	if err := os.Mkdir(cache.KeysDir, 0700); err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := catalog.MarshalPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache.KeysDir, "key.pem"), pem, 0600); err != nil {
		t.Fatal(err)
	}
	return fixture{cache: cache, key: key, now: time.Now().UTC().Truncate(time.Second)}
}

func (f fixture) packageBytes(t *testing.T, now time.Time, ttl time.Duration, runAs string) (*catalog.Package, []byte) {
	t.Helper()
	a := catalog.Action{Name: "identity", Description: "identity", Risk: "read", RunAs: runAs, Exec: []any{"/usr/bin/id"}, Timeout: "1s", MaxOutput: 1024}
	p, err := catalog.Build(&catalog.Catalog{Config: catalog.Config{SchemaVersion: 1, CatalogID: "test"}, Actions: map[string]catalog.Action{a.Name: a}}, catalog.BuildOptions{Now: now, TTL: ttl})
	if err != nil {
		t.Fatal(err)
	}
	data, err := catalog.CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := catalog.Sign(data, catalog.SigningKey{PrivateKey: f.key})
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return p, data
}

func TestCatalogAttacks(t *testing.T) {
	for _, attack := range []string{"tamper", "expired", "rollback", "state-directory-symlink", "state-file-symlink", "catalog-symlink", "catalog-fifo", "unknown-user", "wrong-key", "state-permissions"} {
		t.Run(attack, func(t *testing.T) {
			f := newFixture(t)
			p, data := f.packageBytes(t, f.now, time.Hour, "root")
			switch attack {
			case "tamper":
				data = []byte(strings.Replace(string(data), `"payloadType"`, `"payloadTypX"`, 1))
			case "expired":
				p, data = f.packageBytes(t, f.now.Add(-2*time.Hour), time.Hour, "root")
			case "rollback":
				newer, newData := f.packageBytes(t, f.now.Add(time.Second), time.Hour, "root")
				if _, err := f.cache.Verify(newData, newer.CatalogID, newer.Version, f.now); err != nil {
					t.Fatal(err)
				}
			case "state-directory-symlink":
				if err := os.Symlink(t.TempDir(), f.cache.StateDir); err != nil {
					t.Fatal(err)
				}
			case "state-file-symlink":
				if err := os.Mkdir(f.cache.StateDir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), filepath.Join(f.cache.StateDir, CatalogHash(p.CatalogID)+".version")); err != nil {
					t.Fatal(err)
				}
			case "unknown-user":
				p, data = f.packageBytes(t, f.now, time.Hour, "allowops_nonexistent_test_user_198765")
			case "wrong-key":
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				f.key = key
				p, data = f.packageBytes(t, f.now, time.Hour, "root")
			case "state-permissions":
				if err := os.Mkdir(f.cache.StateDir, 0777); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(f.cache.StateDir, 0777); err != nil {
					t.Fatal(err)
				}
			}
			path := CatalogPath(f.cache.CatalogDir, p.CatalogID, p.Version)
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if attack == "catalog-symlink" {
				outside := filepath.Join(t.TempDir(), "package")
				if err := os.WriteFile(outside, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			} else if attack == "catalog-fifo" {
				makeFIFO(t, path)
			} else if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Prepare(f.cache, Request{CatalogID: p.CatalogID, CatalogVersion: p.Version, Action: "identity", Params: map[string]any{}}); err == nil {
				t.Fatal("attack accepted")
			}
		})
	}
}

func TestHighestVersionConcurrentAndRestart(t *testing.T) {
	f := newFixture(t)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Go(func() {
			p, data := f.packageBytes(t, f.now.Add(time.Duration(i)*time.Second), time.Hour, "root")
			_, _ = f.cache.Verify(data, p.CatalogID, p.Version, f.now)
		})
	}
	workers.Wait()
	p, data := f.packageBytes(t, f.now, time.Hour, "root")
	restarted := f.cache
	if _, err := restarted.Verify(data, p.CatalogID, p.Version, f.now); err == nil {
		t.Fatal("rollback accepted after restart")
	}
}

func TestRequestLimitsAndStrictJSON(t *testing.T) {
	for _, input := range []string{strings.Repeat("x", MaxRequestBytes+1), `{"catalog_id":"test","catalog_id":"evil","catalog_version":1,"action":"a","params":{}}`, `{"catalog_id":"test","catalog_version":1,"action":"a","params":{"a":1,"a":2}}`, `{"catalog_id":"test","catalog_version":1,"action":"a","params":{}} {}`, `null`, `[]`, strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34)} {
		if _, err := ReadRequest(strings.NewReader(input)); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	values, err := DecodeParameters([]byte(`{"number":9007199254740993}`))
	if err != nil || values["number"] != json.Number("9007199254740993") {
		t.Fatalf("integer precision: %v %v", values, err)
	}
}

func TestWirePreservesNonUTF8(t *testing.T) {
	response := Response{Result: executor.Result{ExitCode: 0, StatusCode: 404, Stdout: string([]byte{0xff, 0x00, 0x80})}}
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Response
	if err := DecodeJSON(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Result.Stdout != response.Result.Stdout || decoded.Result.StatusCode != 404 {
		t.Fatalf("bytes changed: %x -> %x", response.Result.Stdout, decoded.Result.Stdout)
	}
}

func FuzzReadRequest(f *testing.F) {
	for _, seed := range []string{`{}`, `{"catalog_id":"test","catalog_version":1,"action":"a","params":{}}`, `{"params":{"a":1,"a":2}}`, `null`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ReadRequest(strings.NewReader(string(data))) })
}

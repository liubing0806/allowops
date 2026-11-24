package pluginhost

import (
	"strconv"
	"testing"
	"time"
)

func TestPluginCacheCopyIsolationAndTTL(t *testing.T) {
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	a, b := newInstanceCache(clock), newInstanceCache(clock)
	v := []byte("value")
	a.Set("k", v, 2*time.Hour)
	v[0] = 'x'
	if _, ok := b.Get("k"); ok {
		t.Fatal("cache shared across instances")
	}
	first, ok := a.Get("k")
	if !ok || string(first) != "value" {
		t.Fatal("Set aliased caller memory")
	}
	first[0] = 'x'
	second, ok := a.Get("k")
	if !ok || string(second) != "value" {
		t.Fatal("Get aliased cache memory")
	}
	now = now.Add(time.Hour)
	if value, ok := a.Get("k"); ok || value != nil {
		t.Fatal("maximum TTL not applied")
	}
	a.Set("k", v, time.Second)
	a.Set("k", v, 0)
	if _, ok := a.Get("k"); ok {
		t.Fatal("nonpositive TTL did not delete")
	}
	a.Set("k", v, time.Second)
	a.Delete("k")
	if _, ok := a.Get("k"); ok {
		t.Fatal("Delete did not remove value")
	}
}

func TestPluginCacheEvictsLeastRecentlyUsed(t *testing.T) {
	cache := newInstanceCache(time.Now)
	for i := range maxCacheEntries {
		cache.Set(strconv.Itoa(i), []byte("x"), time.Minute)
	}
	cache.Get("0")
	cache.Set("new", nil, time.Minute)
	if _, ok := cache.Get("1"); ok {
		t.Fatal("least recently used entry survived")
	}
	if _, ok := cache.Get("0"); !ok {
		t.Fatal("recently used entry was evicted")
	}
	cache.Set("half", make([]byte, maxCacheBytes/2), time.Minute)
	cache.Set("large", make([]byte, maxCacheBytes/2), time.Minute)
	if _, ok := cache.Get("half"); ok {
		t.Fatal("key bytes were omitted from budget")
	}
	cache.Set("oversize", make([]byte, maxCacheBytes), time.Minute)
	if _, ok := cache.Get("oversize"); ok {
		t.Fatal("entry larger than budget was cached")
	}
	if _, ok := cache.Get("large"); !ok {
		t.Fatal("oversize entry removed existing cache entries")
	}
}

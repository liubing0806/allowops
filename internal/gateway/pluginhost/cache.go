package pluginhost

import (
	"container/list"
	"slices"
	"sync"
	"time"
)

const (
	maxCacheEntries = 256
	maxCacheBytes   = 4 << 20
	maxCacheTTL     = time.Hour
)

type cacheEntry struct {
	key     string
	value   []byte
	expires time.Time
}

func (e cacheEntry) size() int { return len(e.key) + len(e.value) }

type instanceCache struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]*list.Element
	lru     list.List
	size    int
}

func newInstanceCache(now func() time.Time) *instanceCache {
	return &instanceCache{now: now, entries: make(map[string]*list.Element)}
}

func (c *instanceCache) Get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	element, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	entry := element.Value.(cacheEntry)
	if !c.now().Before(entry.expires) {
		c.remove(element)
		return nil, false
	}
	c.lru.MoveToFront(element)
	return slices.Clone(entry.value), true
}

func (c *instanceCache) Set(key string, value []byte, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.remove(c.entries[key])
	if ttl <= 0 || len(key) > maxCacheBytes || len(value) > maxCacheBytes-len(key) {
		return
	}
	now := c.now()
	for element := c.lru.Back(); element != nil; {
		previous := element.Prev()
		if !now.Before(element.Value.(cacheEntry).expires) {
			c.remove(element)
		}
		element = previous
	}
	entry := cacheEntry{key, slices.Clone(value), now.Add(min(ttl, maxCacheTTL))}
	for c.lru.Len() >= maxCacheEntries || c.size+entry.size() > maxCacheBytes {
		c.remove(c.lru.Back())
	}
	c.entries[key] = c.lru.PushFront(entry)
	c.size += entry.size()
}

func (c *instanceCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.remove(c.entries[key])
}

func (c *instanceCache) remove(element *list.Element) {
	if element == nil {
		return
	}
	entry := c.lru.Remove(element).(cacheEntry)
	delete(c.entries, entry.key)
	c.size -= entry.size()
}

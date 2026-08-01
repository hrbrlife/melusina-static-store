package envelope

import (
	"sync"
	"time"
)

type MemoryNonceCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewMemoryNonceCache() *MemoryNonceCache {
	return &MemoryNonceCache{seen: make(map[string]time.Time)}
}

func (c *MemoryNonceCache) Claim(scope, nonce string, expiresAt time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for key, exp := range c.seen {
		if exp.Before(now) {
			delete(c.seen, key)
		}
	}
	key := scope + "|" + nonce
	if _, ok := c.seen[key]; ok {
		return false
	}
	c.seen[key] = expiresAt
	return true
}

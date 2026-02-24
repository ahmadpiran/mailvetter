package cache

import (
	"context"
	"log"
	"sync"
	"time"
)

// Item represents a cached value with an expiration time.
type Item struct {
	Value      interface{}
	Expiration int64
}

// Store is a thread-safe in-memory cache.
type Store struct {
	items map[string]Item
	mu    sync.RWMutex
}

// DomainCache is the package-level singleton used by all lookup functions.
var DomainCache = New()

func New() *Store {
	return &Store{
		items: make(map[string]Item),
	}
}

// Set adds a value to the cache with a specific TTL.
func (s *Store) Set(key string, value interface{}, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.items[key] = Item{
		Value:      value,
		Expiration: time.Now().Add(ttl).UnixNano(),
	}
}

// Get retrieves a value. Returns (value, true) on a hit, (nil, false) on a
// miss or if the item has expired. Expired items are not deleted inline here —
// that is the responsibility of the background cleanup goroutine started by
// StartCleanup.
func (s *Store) Get(key string) (interface{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	item, found := s.items[key]
	if !found {
		return nil, false
	}

	if time.Now().UnixNano() > item.Expiration {
		return nil, false
	}

	return item.Value, true
}

// Len returns the number of items currently in the cache, including expired
// ones that have not yet been swept. Useful for monitoring.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items)
}

// Cleanup removes all expired items. It acquires a full write lock for the
// duration of the sweep, so it should only be called from the background
// goroutine managed by StartCleanup — not inline on the hot path.
func (s *Store) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UnixNano()
	removed := 0
	for k, v := range s.items {
		if now > v.Expiration {
			delete(s.items, k)
			removed++
		}
	}
	if removed > 0 {
		log.Printf("[cache] swept %d expired entries, %d remaining", removed, len(s.items))
	}
}

// StartCleanup launches a background goroutine that calls Cleanup on the given
// interval until ctx is cancelled. Call this once during process initialisation.
func StartCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				DomainCache.Cleanup()
			case <-ctx.Done():
				log.Println("[cache] cleanup goroutine exiting")
				return
			}
		}
	}()
}

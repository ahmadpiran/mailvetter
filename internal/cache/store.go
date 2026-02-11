package cache

import (
	"sync"
	"time"
)

// Item represents a cached value with an expiration time.
type Item struct {
	Value      interface{}
	Expiration int64
}

// Store is a thread-safe cache.
type Store struct {
	items map[string]Item
	mu    sync.RWMutex
}

// Global instance (Singleton)
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

// Get retrieves a value. Returns value and exists boolean.
// Returns false if item exists but is expired.
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

// Cleanup removes expired items (Run this in a goroutine if strict memory mgmt is needed)
func (s *Store) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UnixNano()
	for k, v := range s.items {
		if now > v.Expiration {
			delete(s.items, k)
		}
	}
}

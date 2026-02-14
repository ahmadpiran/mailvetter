package proxy

import (
	"fmt"
	"net/url"
	"sync/atomic"
)

// Manager holds the pool of proxies
type Manager struct {
	proxies []*url.URL
	counter uint64
}

// Global instance
var Global *Manager

// Init loads the proxies from a list of strings (e.g., "http://user:pass@ip:port")
func Init(proxyList []string) error {
	var parsed []*url.URL

	for _, p := range proxyList {
		if p == "" {
			continue
		}
		u, err := url.Parse(p)
		if err != nil {
			return fmt.Errorf("invalid proxy URL '%s': %w", p, err)
		}
		parsed = append(parsed, u)
	}

	Global = &Manager{
		proxies: parsed,
		counter: 0,
	}
	return nil
}

// Next returns the next proxy in the rotation.
// It returns nil if no proxies are configured (direct connection).
func (m *Manager) Next() *url.URL {
	if m == nil || len(m.proxies) == 0 {
		return nil
	}

	// Atomic increment ensures thread-safety across concurrent workers
	n := atomic.AddUint64(&m.counter, 1)
	return m.proxies[(n-1)%uint64(len(m.proxies))]
}

// Enabled checks if proxying is active
func Enabled() bool {
	return Global != nil && len(Global.proxies) > 0
}

package proxy

import (
	"fmt"
	"net/url"
	"sync/atomic"
)

type Manager struct {
	proxies []*url.URL
	counter uint64
}

var Global *Manager
var Semaphore chan struct{}
var SMTPEnabled bool

// Init loads the proxies and sets the dynamic concurrency limit and SMTP toggle
func Init(proxyList []string, limit int, enableSMTP bool) error {
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

	// Dynamic Logic: If no limit is provided, default to the number of proxies
	if limit <= 0 {
		limit = len(parsed)
		if limit == 0 {
			limit = 10 // Failsafe
		}
	}

	// Initialize the dynamic traffic light
	Semaphore = make(chan struct{}, limit)
	SMTPEnabled = enableSMTP

	Global = &Manager{
		proxies: parsed,
		counter: 0,
	}
	return nil
}

func (m *Manager) Next() *url.URL {
	if m == nil || len(m.proxies) == 0 {
		return nil
	}
	n := atomic.AddUint64(&m.counter, 1)
	return m.proxies[(n-1)%uint64(len(m.proxies))]
}

func Enabled() bool {
	return Global != nil && len(Global.proxies) > 0
}

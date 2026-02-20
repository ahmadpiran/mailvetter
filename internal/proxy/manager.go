package proxy

import (
	"fmt"
	"net"
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

// Init loads the proxies and sets the dynamic concurrency limit
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

		// --- Pre-Resolve the Proxy Hostname to an IP ---
		// This prevents the Go DNS resolver from crashing under high concurrency
		host := u.Hostname()
		port := u.Port()

		// If it's a hostname (not already an IP address), resolve it
		if net.ParseIP(host) == nil {
			ips, err := net.LookupIP(host)
			if err == nil && len(ips) > 0 {
				// Prefer IPv4
				resolvedIP := ips[0].String()
				for _, ip := range ips {
					if ip.To4() != nil {
						resolvedIP = ip.String()
						break
					}
				}
				// Reconstruct the URL with the raw IP address
				if port != "" {
					u.Host = net.JoinHostPort(resolvedIP, port)
				} else {
					u.Host = resolvedIP
				}
				fmt.Printf("[DEBUG] Pre-resolved proxy %s to IP: %s\n", host, u.Host)
			}
		}

		parsed = append(parsed, u)
	}

	if limit <= 0 {
		limit = len(parsed)
		if limit == 0 {
			limit = 10
		}
	}

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

package proxy

import (
	"context"
	"log"
	"net"
	"time"

	netproxy "golang.org/x/net/proxy"
)

// DialContext behaves exactly like net.Dialer.DialContext, but automatically
// routes the TCP connection through a SOCKS5 proxy if the manager is enabled.
func DialContext(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	directDialer := &net.Dialer{Timeout: timeout}

	if !Enabled() {
		return directDialer.DialContext(ctx, network, addr)
	}

	u := Global.Next()
	if u == nil {
		return directDialer.DialContext(ctx, network, addr)
	}

	log.Printf("[DEBUG-PROXY] Dialing %s via proxy %s", addr, u.Host)
	start := time.Now()

	// Create the proxy dialer (This supports "socks5://user:pass@ip:port" URLs natively)
	pdialer, err := netproxy.FromURL(u, directDialer)
	if err != nil {
		log.Printf("[DEBUG-PROXY] Failed to parse proxy URL: %v", err)
		return nil, err
	}

	// Try to use ContextDialer if the underlying proxy supports it (for timeout handling)
	var conn net.Conn
	if cdialer, ok := pdialer.(netproxy.ContextDialer); ok {
		conn, err = cdialer.DialContext(ctx, network, addr)
	} else {
		conn, err = pdialer.Dial(network, addr)
	}

	if err != nil {
		log.Printf("[DEBUG-PROXY] FAILED to dial %s. Took %v. Err: %v", addr, time.Since(start), err)
	} else {
		log.Printf("[DEBUG-PROXY] SUCCESS connected to %s. Took %v", addr, time.Since(start))
	}

	return conn, err
}

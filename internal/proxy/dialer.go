package proxy

import (
	"context"
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

	// Create the proxy dialer (This supports "socks5://user:pass@ip:port" URLs natively)
	pdialer, err := netproxy.FromURL(u, directDialer)
	if err != nil {
		return nil, err
	}

	// Try to use ContextDialer if the underlying proxy supports it (for timeout handling)
	if cdialer, ok := pdialer.(netproxy.ContextDialer); ok {
		return cdialer.DialContext(ctx, network, addr)
	}

	// Fallback to standard Dial
	return pdialer.Dial(network, addr)
}

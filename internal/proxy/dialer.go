package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	netproxy "golang.org/x/net/proxy"
)

// proxyConn wraps net.Conn so we can safely release our Semaphore token
// when the SMTP client closes the connection.
type proxyConn struct {
	net.Conn
	releaseOnce sync.Once // Ensures we never accidentally release a token twice
}

func (pc *proxyConn) Close() error {
	pc.releaseOnce.Do(func() {
		<-Semaphore // Give the slot back to the global pool
	})
	return pc.Conn.Close()
}

func DialContext(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	directDialer := &net.Dialer{Timeout: timeout}

	if !Enabled() {
		return directDialer.DialContext(ctx, network, addr)
	}

	u := Global.Next()
	if u == nil {
		return directDialer.DialContext(ctx, network, addr)
	}

	// Respect the Context Timeout while waiting in line
	select {
	case Semaphore <- struct{}{}:
		// Successfully grabbed a proxy slot! Proceed.
	case <-ctx.Done():
		// The worker timeout hit before we could get a proxy slot
		return nil, fmt.Errorf("timeout waiting for proxy slot: %w", ctx.Err())
	}

	// Force Local DNS Resolution
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		if net.ParseIP(host) == nil {
			ips, lookupErr := net.LookupIP(host)
			if lookupErr == nil && len(ips) > 0 {
				// Prefer IPv4 because some proxies don't support IPv6
				resolvedIP := ips[0].String()
				for _, ip := range ips {
					if ip.To4() != nil {
						resolvedIP = ip.String()
						break
					}
				}
				addr = net.JoinHostPort(resolvedIP, port)
				log.Printf("[DEBUG-PROXY] Resolved target locally to IP: %s", addr)
			}
		}
	}

	log.Printf("[DEBUG-PROXY] Dialing %s via proxy %s", addr, u.Host)
	start := time.Now()

	pdialer, err := netproxy.FromURL(u, directDialer)
	if err != nil {
		<-Semaphore // Release token on error
		log.Printf("[DEBUG-PROXY] Failed to parse proxy URL: %v", err)
		return nil, err
	}

	var conn net.Conn
	if cdialer, ok := pdialer.(netproxy.ContextDialer); ok {
		conn, err = cdialer.DialContext(ctx, network, addr)
	} else {
		conn, err = pdialer.Dial(network, addr)
	}

	if err != nil {
		<-Semaphore // Release token on network rejection
		log.Printf("[DEBUG-PROXY] FAILED to dial %s. Took %v. Err: %v", addr, time.Since(start), err)
		return nil, err
	}

	log.Printf("[DEBUG-PROXY] SUCCESS connected to %s. Took %v", addr, time.Since(start))

	// SUCCESS! Return the wrapped connection
	return &proxyConn{Conn: conn}, nil
}

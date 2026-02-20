package proxy

import (
	"context"
	"log"
	"net"
	"time"

	netproxy "golang.org/x/net/proxy"
)

// proxyConn wraps net.Conn so we can safely release our Semaphore token
// when the SMTP client closes the connection.
type proxyConn struct {
	net.Conn
	released bool
}

func (pc *proxyConn) Close() error {
	if !pc.released {
		<-Semaphore // Give the slot back to the global pool
		pc.released = true
	}
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

	Semaphore <- struct{}{}

	// Force Local DNS Resolution
	// By default, Go sends the hostname to the proxy server. If the proxy
	// does not support DNS, it fails. We resolve it to an IP locally first.
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		// Only look up if it's not already an IP address
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

	// SUCCESS! Return the wrapped connection so the Semaphore releases on Close()
	return &proxyConn{Conn: conn, released: false}, nil
}

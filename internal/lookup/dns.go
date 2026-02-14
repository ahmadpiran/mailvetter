package lookup

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// MXRecord holds the simplified result of an MX lookup
type MXRecord struct {
	Host string
	Pref uint16
}

// CheckDNS performs the initial domain validation and MX lookup.
func CheckDNS(ctx context.Context, domain string) ([]*net.MX, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// We must use a direct dialer for DNS because
			// standard SOCKS5 proxies do not support UDP traffic.
			d := net.Dialer{
				Timeout: 3 * time.Second,
			}
			return d.DialContext(ctx, network, address)
		},
	}

	mxRecords, err := r.LookupMX(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed: %w", err)
	}

	if len(mxRecords) == 0 {
		return nil, fmt.Errorf("no MX records found for domain")
	}

	// Strip the trailing dot from Go's FQDN format.
	// SOCKS5 proxies will fail to resolve hostnames if they end in a dot.
	for _, mx := range mxRecords {
		mx.Host = strings.TrimSuffix(mx.Host, ".")
	}

	return mxRecords, nil
}

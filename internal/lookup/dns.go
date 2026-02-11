package lookup

import (
	"context"
	"fmt"
	"net"
	"time"
)

// MXRecord holds the simplified result of an MX lookup
type MXRecord struct {
	Host string
	Pref uint16
}

// CheckDNS performs the initial domain validation and MX lookup.
// It returns a list of MX records or an error if the domain is invalid.
func CheckDNS(ctx context.Context, domain string) ([]*net.MX, error) {
	// 1. Set a strict timeout.
	// In a high-perf SaaS, we can't wait 30 seconds for a bad DNS server.
	// We use a custom Resolver to enforce this timeout.
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 3 * time.Second, // Fail fast if DNS is slow
			}
			return d.DialContext(ctx, network, address)
		},
	}

	// 2. Perform the Lookup
	// context.Background() is used here for simplicity in Phase 1,
	// but we will eventually pass down a request context.
	mxRecords, err := r.LookupMX(ctx, domain)
	if err != nil {
		// If generic error, we check if it's a "No Such Host" error
		return nil, fmt.Errorf("DNS lookup failed: %w", err)
	}

	if len(mxRecords) == 0 {
		return nil, fmt.Errorf("no MX records found for domain")
	}

	return mxRecords, nil
}

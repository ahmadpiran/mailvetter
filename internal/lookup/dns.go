package lookup

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// MXRecord holds the simplified result of an MX lookup.
// Using a value type rather than *net.MX avoids mutating structs that
// Go's internal resolver may have cached.
type MXRecord struct {
	Host string
	Pref uint16
}

// CheckDNS performs the initial domain validation and MX lookup.
// Returns a slice of MXRecord values sorted by preference (lowest = highest priority).
func CheckDNS(ctx context.Context, domain string) ([]MXRecord, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			// We must use a direct dialer for DNS because standard SOCKS5 proxies
			// do not support UDP traffic.
			//
			// Respect the caller's context deadline rather than always
			// using a fixed 3-second wall-clock timeout. If the caller's budget
			// is already tight, a 3-second dial can block well past cancellation.
			timeout := 3 * time.Second
			if deadline, ok := dialCtx.Deadline(); ok {
				if remaining := time.Until(deadline); remaining < timeout {
					timeout = remaining
				}
			}
			d := net.Dialer{Timeout: timeout}

			// Try the system-provided DNS address first, then fall back to
			// Google's public resolver if the system resolver is unreachable.
			// This prevents a misconfigured /etc/resolv.conf from silently
			// causing all DNS lookups to fail.
			conn, err := d.DialContext(dialCtx, network, address)
			if err != nil {
				conn, err = d.DialContext(dialCtx, "udp", "8.8.8.8:53")
			}
			return conn, err
		},
	}

	rawRecords, err := r.LookupMX(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed: %w", err)
	}

	if len(rawRecords) == 0 {
		return nil, fmt.Errorf("no MX records found for domain")
	}

	// Copy into our own value-typed MXRecord slice rather than mutating
	// the *net.MX pointers returned by LookupMX. Go's resolver may cache those
	// structs internally, and stripping the trailing dot in-place would corrupt
	// any subsequent lookup that reuses the same cached pointer.
	records := make([]MXRecord, 0, len(rawRecords))
	for _, mx := range rawRecords {
		records = append(records, MXRecord{
			// Strip the trailing dot from Go's FQDN format.
			// SOCKS5 proxies will fail to resolve hostnames ending in a dot.
			Host: strings.TrimSuffix(mx.Host, "."),
			Pref: mx.Pref,
		})
	}

	return records, nil
}

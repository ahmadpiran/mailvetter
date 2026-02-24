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
//
// BUG FIXED (issue #10): The previous fallback dialer hardcoded "udp" as the
// network protocol regardless of what the resolver originally requested:
//
//	conn, err := d.DialContext(dialCtx, network, address)   // could be "tcp"
//	if err != nil {
//	    conn, err = d.DialContext(dialCtx, "udp", "8.8.8.8:53") // always udp
//	}
//
// DNS responses larger than 512 bytes (common for domains with many MX, SPF,
// or DMARC records) cause the server to set the TC (truncated) bit in a UDP
// response. The resolver is then expected to retry over TCP to retrieve the
// full response. If the system resolver initiated a TCP connection and the
// fallback silently downgraded it to UDP, the response could be silently
// truncated — returning an incomplete set of MX records with no error, which
// causes the verifier to probe the wrong mail server.
//
// The fix: the fallback uses the same `network` value the resolver originally
// requested, preserving the protocol contract. The Google DNS address is still
// used as the fallback *destination*, but over the correct transport.
func CheckDNS(ctx context.Context, domain string) ([]MXRecord, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			// Respect the caller's context deadline rather than always using a
			// fixed wall-clock timeout. If the caller's budget is already tight,
			// a 3-second dial can block well past cancellation.
			timeout := 3 * time.Second
			if deadline, ok := dialCtx.Deadline(); ok {
				if remaining := time.Until(deadline); remaining < timeout {
					timeout = remaining
				}
			}
			d := net.Dialer{Timeout: timeout}

			// Try the system-provided DNS address first.
			conn, err := d.DialContext(dialCtx, network, address)
			if err != nil {
				// Fall back to Google's public resolver if the system resolver
				// is unreachable (e.g. misconfigured /etc/resolv.conf).
				//
				// FIX: use `network` here, not the hardcoded string "udp".
				// The resolver may have requested "tcp" — for instance when a
				// previous UDP response was truncated and it is retrying over
				// TCP to retrieve the full record set. Downgrading that retry
				// to UDP would silently return a truncated response with no
				// error, producing an incomplete MX list and causing the
				// verifier to probe the wrong mail server.
				conn, err = d.DialContext(dialCtx, network, "8.8.8.8:53")
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

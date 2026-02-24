package lookup

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"time"
)

const hibpURL = "https://haveibeenpwned.com/api/v3/breachedaccount/"

type hibpBreach struct {
	Name string `json:"Name"`
}

// CheckHIBP queries the HaveIBeenPwned v3 API and returns the number of
// breaches the given email address has appeared in. Returns 0 if the API
// key is absent, the address is clean, or any unrecoverable error occurs.

// Email local parts are permitted by RFC 5321 to contain characters that are
// not safe in a URL path segment — most commonly `+` (valid in a local part,
// means space in a query string) and `%` (valid in a local part, begins a
// percent-encoding sequence in a URL). Concatenating such an address without
// encoding it produces a malformed URL. http.NewRequestWithContext returns an
// error on every attempt, the function returns 0 for every such address, and
// the retry loop burns two attempts and 500 ms for nothing.
//
// The fix is to wrap the email with url.PathEscape before interpolation.
// PathEscape encodes everything that is not a valid path character, including
// `+`, `%`, `?`, `#`, and space, while leaving the `@` sign and alphanumerics
// untouched — which is exactly what the HIBP API path segment requires.
func CheckHIBP(ctx context.Context, email, apiKey string, pURL *url.URL) int {
	if apiKey == "" {
		return 0
	}

	// PathEscape rather than QueryEscape: the email sits in the URL *path*,
	// not in a query parameter. QueryEscape would encode `@` as `%40` which
	// some WAFs and API gateways reject when it appears in a path segment.
	// PathEscape leaves `@` intact, matching the format the HIBP API expects.
	escapedEmail := url.PathEscape(email)
	endpoint := hibpURL + escapedEmail + "?truncateResponse=true"

	for attempt := 1; attempt <= 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			// With a correctly encoded URL this branch should never be reached
			// under normal operation. Log it so any future edge-case is visible.
			log.Printf("[DEBUG] HIBP: failed to build request for %s (attempt %d): %v", email, attempt, err)
			return 0
		}

		req.Header.Set("hibp-api-key", apiKey)
		req.Header.Set("User-Agent", "Mailvetter-Verifier")

		currentProxy := pURL
		if attempt == 2 {
			currentProxy = nil
		}

		resp, err := DoProxiedRequest(req, currentProxy)
		if err != nil {
			if attempt == 1 {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return 0
		}

		switch resp.StatusCode {
		case 200:
			var breaches []hibpBreach
			if err := json.NewDecoder(resp.Body).Decode(&breaches); err != nil {
				resp.Body.Close()
				return 0
			}
			resp.Body.Close()
			return len(breaches)

		case 404:
			// 404 means the address exists but has no recorded breaches — clean.
			resp.Body.Close()
			return 0

		case 429:
			resp.Body.Close()
			if attempt == 1 {
				log.Printf("[DEBUG] HIBP rate limit hit for %s, backing off and retrying", email)
				select {
				case <-time.After(1600 * time.Millisecond):
				case <-ctx.Done():
					return 0
				}
				continue
			}
			return 0

		default:
			resp.Body.Close()
			if attempt == 1 {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return 0
		}
	}
	return 0
}

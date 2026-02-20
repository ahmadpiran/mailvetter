package lookup

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

const hibpURL = "https://haveibeenpwned.com/api/v3/breachedaccount/"

// hibpBreach is a named type for decoding HIBP breach entries.
// Using a concrete struct rather than []interface{} makes decode failures
// more explicit and documents the expected response shape.
type hibpBreach struct {
	Name string `json:"Name"`
}

// CheckHIBP queries the HaveIBeenPwned API and returns the number of breaches
// the given email appears in. Requires a valid API key.
// Returns 0 on error, no breaches found, or missing API key.
func CheckHIBP(ctx context.Context, email, apiKey string) int {
	if apiKey == "" {
		return 0
	}

	req, err := http.NewRequestWithContext(ctx, "GET", hibpURL+email+"?truncateResponse=true", nil)
	if err != nil {
		return 0
	}

	req.Header.Set("hibp-api-key", apiKey)
	req.Header.Set("User-Agent", "Mailvetter-Verifier")

	resp, err := DoProxiedRequest(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		// Decode into a named struct slice rather than []interface{}.
		// This is more explicit about the expected response shape and will
		// correctly return 0 on a malformed response rather than silently
		// counting garbage entries.
		var breaches []hibpBreach
		if err := json.NewDecoder(resp.Body).Decode(&breaches); err != nil {
			return 0
		}
		return len(breaches)

	case 404:
		// 404 means the account was not found in any breach — this is the happy path.
		return 0

	case 429:
		// HIBP enforces a rate limit (~1 req/1500ms per key) and returns 429
		// when exceeded. Previously this fell through and returned 0, which is
		// indistinguishable from "no breaches found" — silently discarding real
		// breach history. We now back off and retry once before giving up.
		log.Printf("[DEBUG] HIBP rate limit hit for %s, backing off and retrying", email)

		select {
		case <-time.After(1600 * time.Millisecond):
			// Backoff complete — retry once.
		case <-ctx.Done():
			return 0
		}

		retryReq, err := http.NewRequestWithContext(ctx, "GET", hibpURL+email+"?truncateResponse=true", nil)
		if err != nil {
			return 0
		}
		retryReq.Header.Set("hibp-api-key", apiKey)
		retryReq.Header.Set("User-Agent", "Mailvetter-Verifier")

		retryResp, err := DoProxiedRequest(retryReq)
		if err != nil {
			return 0
		}
		defer retryResp.Body.Close()

		if retryResp.StatusCode == 200 {
			var breaches []hibpBreach
			if err := json.NewDecoder(retryResp.Body).Decode(&breaches); err != nil {
				return 0
			}
			return len(breaches)
		}
		return 0

	default:
		return 0
	}
}

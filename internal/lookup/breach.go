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

func CheckHIBP(ctx context.Context, email, apiKey string, pURL *url.URL) int {
	if apiKey == "" {
		return 0
	}

	for attempt := 1; attempt <= 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", hibpURL+email+"?truncateResponse=true", nil)
		if err != nil {
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

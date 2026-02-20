package lookup

import (
	"context"
	"encoding/json"
	"net/http"
)

const hibpURL = "https://haveibeenpwned.com/api/v3/breachedaccount/"

// CheckHIBP queries the HaveIBeenPwned API (requires API key).
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

	if resp.StatusCode == 200 {
		var breaches []interface{}
		if err := json.NewDecoder(resp.Body).Decode(&breaches); err == nil {
			return len(breaches)
		}
	}

	return 0
}

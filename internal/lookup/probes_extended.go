package lookup

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// CheckAdobe checks the Adobe Identity Management endpoint.
// This is excellent for creative professionals.
func CheckAdobe(ctx context.Context, email string) bool {
	url := "https://auth.services.adobe.com/signin/v2/users/accounts"

	payload := map[string]string{
		"username": email,
	}
	jsonPayload, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-IMS-ClientId", "AdobeID_v2_1") // Public Client ID
	req.Header.Set("User-Agent", getRandomUserAgent())

	resp, err := DoProxiedRequest(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Adobe returns 200 with a JSON list of accounts if the user exists.
	// We check if the response body contains "accountType" which implies a valid user object.
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	bodyStr := buf.String()

	return (resp.StatusCode == 200 && len(bodyStr) > 50 && contains(bodyStr, "accountType"))
}

// CheckDomainAge queries RDAP to find the domain creation date.
// It uses rdap.org as a bootstrap to find the correct TLD server.
func CheckDomainAge(ctx context.Context, domain string) int {
	// 1. Query the RDAP bootstrap service
	url := "https://rdap.org/domain/" + domain

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("Accept", "application/rdap+json")

	// Use the shared client (handles redirects automatically)
	resp, err := DoProxiedRequest(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0
	}

	// 2. Parse the RDAP JSON
	// We only care about the "events" array to find "registration" or "creation"
	var rdap struct {
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rdap); err != nil {
		return 0
	}

	// 3. Find the oldest date
	var created time.Time
	for _, event := range rdap.Events {
		if event.Action == "registration" || event.Action == "creation" {
			// RDAP dates are standard RFC3339 (ISO 8601)
			t, err := time.Parse(time.RFC3339, event.Date)
			if err == nil {
				created = t
				break
			}
		}
	}

	if created.IsZero() {
		return 0
	}

	// 4. Calculate Age in Days
	days := int(time.Since(created).Hours() / 24)
	return days
}

// Helpers
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && len(s) >= len(substr) &&
		(s == substr || (len(s) > len(substr) && searchStr(s, substr)))
}

func searchStr(s, substr string) bool {
	for i := 0; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

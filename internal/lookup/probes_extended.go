package lookup

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// CheckAdobe checks the Adobe Identity Management endpoint.
// A 200 response containing an accountType field indicates a valid Adobe account.
// This is a strong signal for creative professionals.
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

	if resp.StatusCode != 200 {
		return false
	}

	// ReadFrom error is no longer silently discarded.
	// A partial body due to a dropped connection would previously produce an
	// incomplete string that might return false incorrectly rather than
	// being treated as a transient failure.
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return false
	}
	bodyStr := buf.String()

	// Replaced hand-rolled contains/searchStr helpers with strings.Contains.
	// The previous implementation was a manual reimplementation of exactly what
	// strings.Contains does, with more code and no benefit.
	return len(bodyStr) > 50 && strings.Contains(bodyStr, "accountType")
}

// CheckDomainAge queries RDAP to find the domain creation date and returns
// the domain's age in days. Returns 0 if the age cannot be determined.
func CheckDomainAge(ctx context.Context, domain string) int {
	url := "https://rdap.org/domain/" + domain

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := DoProxiedRequest(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0
	}

	var rdap struct {
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rdap); err != nil {
		return 0
	}

	// Previously the loop broke on the first registration/creation event found.
	// RDAP responses may contain multiple events of the same type (e.g. after a
	// transfer or re-registration), and the earliest one may not appear first.
	// We now scan all events and keep the oldest date seen.
	var created time.Time
	for _, event := range rdap.Events {
		if event.Action == "registration" || event.Action == "creation" {
			t, err := time.Parse(time.RFC3339, event.Date)
			if err != nil {
				continue
			}
			if created.IsZero() || t.Before(created) {
				created = t
			}
		}
	}

	if created.IsZero() {
		return 0
	}

	days := int(time.Since(created).Hours() / 24)
	return days
}

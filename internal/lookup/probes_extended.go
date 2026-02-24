package lookup

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func CheckAdobe(ctx context.Context, email string, pURL *url.URL) bool {
	target := "https://auth.services.adobe.com/signin/v2/users/accounts"

	payload := map[string]string{
		"username": email,
	}
	jsonPayload, _ := json.Marshal(payload)

	for attempt := 1; attempt <= 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "POST", target, bytes.NewBuffer(jsonPayload))
		if err != nil {
			return false
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-IMS-ClientId", "AdobeID_v2_1")
		req.Header.Set("User-Agent", getRandomUserAgent())

		resp, err := DoProxiedRequest(req, pURL)
		if err != nil {
			if attempt == 1 {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return false
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			return false
		}

		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			resp.Body.Close()
			if attempt == 1 {
				continue
			}
			return false
		}
		resp.Body.Close()

		bodyStr := buf.String()
		return len(bodyStr) > 50 && strings.Contains(bodyStr, "accountType")
	}
	return false
}

func CheckDomainAge(ctx context.Context, domain string, pURL *url.URL) int {
	target := "https://rdap.org/domain/" + domain

	for attempt := 1; attempt <= 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			return 0
		}
		req.Header.Set("Accept", "application/rdap+json")

		resp, err := DoProxiedRequest(req, pURL)
		if err != nil {
			if attempt == 1 {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return 0
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			return 0
		}

		var rdap struct {
			Events []struct {
				Action string `json:"eventAction"`
				Date   string `json:"eventDate"`
			} `json:"events"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&rdap); err != nil {
			resp.Body.Close()
			return 0
		}
		resp.Body.Close()

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

		return int(time.Since(created).Hours() / 24)
	}
	return 0
}

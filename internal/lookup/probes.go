package lookup

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"mailvetter/internal/proxy"
)

var sharedClient = &http.Client{
	// The 15-second client-level Timeout has been removed.
	// All probe requests are made with http.NewRequestWithContext, so the caller's
	// context deadline is already the primary cancellation mechanism. A hard client
	// timeout here would silently override context deadlines shorter than 15s,
	// causing probes to block well past the point the caller has given up.
	// A 20-second backstop is kept only as a last resort for contexts with no deadline.
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			if proxy.Enabled() {
				return proxy.Global.Next(), nil
			}
			return nil, nil
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	},
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

func getRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

// DoProxiedRequest executes an HTTP request, routing it through the proxy semaphore
// when a proxy is enabled to cap concurrent outbound connections.
func DoProxiedRequest(req *http.Request) (*http.Response, error) {
	if proxy.Enabled() {
		// Semaphore acquisition is now context-aware.
		// Previously this blocked unconditionally, meaning a caller with an expired
		// context would sit here waiting for a free proxy slot indefinitely.
		select {
		case proxy.Semaphore <- struct{}{}:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		defer func() { <-proxy.Semaphore }()
	}
	return sharedClient.Do(req)
}

// --- INFRASTRUCTURE ---

func CheckOffice365(ctx context.Context, domain string) bool {
	mxRecords, err := CheckDNS(ctx, domain)
	if err == nil {
		for _, mx := range mxRecords {
			if strings.Contains(mx.Host, "outlook.com") || strings.Contains(mx.Host, "protection.outlook.com") {
				return true
			}
		}
	}
	return false
}

func CheckGoogleWorkspace(ctx context.Context, domain string) bool {
	mxRecords, err := CheckDNS(ctx, domain)
	if err == nil {
		for _, mx := range mxRecords {
			if strings.Contains(mx.Host, "google.com") || strings.Contains(mx.Host, "googlemail.com") {
				return true
			}
		}
	}
	return false
}

// --- APP PROBES ---

// CheckTeamsPresence verifies user existence via the Microsoft login endpoint.
// We no longer require sipfederationtls SRV records, as modern O365 tenants
// often omit them, which previously caused massive false negatives.
func CheckTeamsPresence(ctx context.Context, email, domain string) bool {
	return CheckMicrosoftLogin(ctx, email)
}

// CheckGoogleCalendar probes the CalDAV endpoint for the given email.
// A 401 response indicates the user exists but requires authentication.
// Note: PROPFIND would be more semantically appropriate here, but many
// CalDAV servers do not respond consistently to it without auth headers.
func CheckGoogleCalendar(ctx context.Context, email string) bool {
	url := fmt.Sprintf("https://calendar.google.com/calendar/dav/%s/events", email)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", getRandomUserAgent())

	resp, err := DoProxiedRequest(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 401 || resp.StatusCode == 200
}

// CheckSharePoint probes the user's personal OneDrive/SharePoint URL.
// A 401 or 403 response indicates the personal site exists but requires auth.
func CheckSharePoint(ctx context.Context, email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	// Microsoft strictly replaces dots and hyphens in the local-part
	// with underscores for SharePoint URLs.
	// "anirudh.kataruka" MUST become "anirudh_kataruka"
	user := strings.ReplaceAll(parts[0], ".", "_")
	user = strings.ReplaceAll(user, "-", "_")
	domain := parts[1]

	domainParts := strings.Split(domain, ".")
	if len(domainParts) < 2 {
		return false
	}

	baseTenant := domainParts[0]
	userPath := fmt.Sprintf("%s_%s", user, strings.ReplaceAll(domain, ".", "_"))

	// Microsoft sometimes uses the base domain, or strips the TLD completely.
	// We'll use the standard baseTenant format.
	url := fmt.Sprintf("https://%s-my.sharepoint.com/personal/%s", baseTenant, userPath)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", getRandomUserAgent())

	resp, err := DoProxiedRequest(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// 403/401 means the tenant and user exist, but it's private.
	// 200 means it's public. 404 means the user does not exist.
	return resp.StatusCode == 403 || resp.StatusCode == 401 || resp.StatusCode == 200
}

// --- SOCIAL PROBES ---

func CheckGravatar(ctx context.Context, email string) bool {
	cleanEmail := strings.TrimSpace(strings.ToLower(email))
	hash := md5.Sum([]byte(cleanEmail))
	hashString := fmt.Sprintf("%x", hash)
	url := fmt.Sprintf("https://www.gravatar.com/avatar/%s?d=404", hashString)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", getRandomUserAgent())

	resp, err := DoProxiedRequest(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func CheckGitHub(ctx context.Context, email string) bool {
	url := fmt.Sprintf("https://api.github.com/search/users?q=%s+in:email", email)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", getRandomUserAgent())

	resp, err := DoProxiedRequest(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var result struct {
			TotalCount int `json:"total_count"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			return result.TotalCount > 0
		}
	}
	return false
}

type MicrosoftCredentialResponse struct {
	Username       string `json:"Username"`
	IfExistsResult int    `json:"IfExistsResult"`
}

func CheckMicrosoftLogin(ctx context.Context, email string) bool {
	// The Office 365 Autodiscover API is a highly reliable, unauthenticated endpoint
	// that bypasses Catch-Alls and is not heavily rate-limited.
	targetURL := fmt.Sprintf("https://outlook.office365.com/autodiscover/autodiscover.json?Email=%s&Protocol=Autodiscoverv1", url.QueryEscape(email))

	// FIX: We MUST use a custom HTTP client to PREVENT following redirects.
	// A valid user returns 200 OK. An invalid user returns a 302 Redirect.
	// If we follow the redirect, it breaks the logic.
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Stop immediately on 302!
		},
		Transport: sharedClient.Transport,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", getRandomUserAgent())

	// Route through your proxy manager if enabled
	if proxy.Enabled() {
		select {
		case proxy.Semaphore <- struct{}{}:
		case <-ctx.Done():
			return false
		}
		defer func() { <-proxy.Semaphore }()
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// 200 OK means Microsoft successfully resolved the exact mailbox.
	return resp.StatusCode == 200
}

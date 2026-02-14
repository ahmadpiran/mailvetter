package lookup

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"mailvetter/internal/proxy"
)

// sharedClient dynamically routes traffic through proxies if they are enabled
var sharedClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		// This function runs on EVERY request
		Proxy: func(req *http.Request) (*url.URL, error) {
			if proxy.Enabled() {
				return proxy.Global.Next(), nil
			}
			return nil, nil // Fallback to direct connection if no proxies
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

func CheckTeamsPresence(ctx context.Context, email, domain string) bool {
	_, addrs, err := net.LookupSRV("sipfederationtls", "tcp", domain)
	if err != nil || len(addrs) == 0 {
		_, addrs, err = net.LookupSRV("sip", "tls", domain)
		if err != nil || len(addrs) == 0 {
			return false
		}
	}
	return CheckMicrosoftLogin(ctx, email)
}

func CheckGoogleCalendar(ctx context.Context, email string) bool {
	url := fmt.Sprintf("https://calendar.google.com/calendar/dav/%s/events", email)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", getRandomUserAgent())

	resp, err := sharedClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 401 || resp.StatusCode == 200
}

func CheckSharePoint(ctx context.Context, email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	user := parts[0]
	domain := parts[1]
	baseTenant := strings.Split(domain, ".")[0]
	userPath := fmt.Sprintf("%s_%s", user, strings.ReplaceAll(domain, ".", "_"))
	url := fmt.Sprintf("https://%s-my.sharepoint.com/personal/%s", baseTenant, userPath)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", getRandomUserAgent())

	resp, err := sharedClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 403 || resp.StatusCode == 401 || resp.StatusCode == 200
}

// --- SOCIAL PROBES ---

// CheckGravatar checks for a profile image.
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

	resp, err := sharedClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// CheckGitHub checks if the email is associated with a GitHub user.
// Note: This hits the unauthenticated API search, which has rate limits.
// For production, use a token: req.Header.Set("Authorization", "token ...")
func CheckGitHub(ctx context.Context, email string) bool {
	// GitHub Search API: q=email:user@domain.com type:user
	// Note: Email search often requires auth.
	// Fallback Strategy: Check if the user part matches a username? No, that's inaccurate.
	// Accurate Strategy: Commit Search.

	// Since unauthenticated email search is restricted, we'll try a commit patch lookup technique
	// or simply use the search endpoint and handle the 422/403 gracefully.

	url := fmt.Sprintf("https://api.github.com/search/users?q=%s+in:email", email)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", getRandomUserAgent())

	resp, err := sharedClient.Do(req)
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
	url := "https://login.microsoftonline.com/common/GetCredentialType"
	payload := map[string]string{"username": email}
	jsonPayload, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", getRandomUserAgent())

	resp, err := sharedClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}

	var result MicrosoftCredentialResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false
	}
	return result.IfExistsResult == 0
}

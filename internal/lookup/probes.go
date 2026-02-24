package lookup

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"mailvetter/internal/proxy"
)

type contextKey string

const proxyCtxKey contextKey = "proxyURL"

var sharedClient = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			if p, ok := req.Context().Value(proxyCtxKey).(*url.URL); ok && p != nil {
				return p, nil
			}
			return nil, nil
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	},
}

// sharedNoRedirectClient reuses the same underlying Transport (and therefore
// the same connection pool) as sharedClient, but does not follow redirects.
// Used by probes where a redirect itself is the meaningful signal (e.g.
// SharePoint 302, Microsoft Autodiscover 302).
var sharedNoRedirectClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: sharedClient.Transport,
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

func getRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func DoProxiedRequest(req *http.Request, pURL *url.URL) (*http.Response, error) {
	reqCtx := context.WithValue(req.Context(), proxyCtxKey, pURL)
	req = req.WithContext(reqCtx)

	if pURL != nil && proxy.Enabled() {
		select {
		case proxy.Semaphore <- struct{}{}:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		defer func() { <-proxy.Semaphore }()
	}
	return sharedClient.Do(req)
}

// doProxiedNoRedirectRequest is identical to DoProxiedRequest but uses
// sharedNoRedirectClient so that HTTP redirects are not followed.
func doProxiedNoRedirectRequest(req *http.Request, pURL *url.URL) (*http.Response, error) {
	reqCtx := context.WithValue(req.Context(), proxyCtxKey, pURL)
	req = req.WithContext(reqCtx)

	if pURL != nil && proxy.Enabled() {
		select {
		case proxy.Semaphore <- struct{}{}:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		defer func() { <-proxy.Semaphore }()
	}
	return sharedNoRedirectClient.Do(req)
}

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

func CheckTeamsPresence(ctx context.Context, email, domain string, pURL *url.URL) bool {
	return CheckMicrosoftLogin(ctx, email, pURL)
}

// CheckGoogleCalendar probes the CalDAV endpoint to detect whether the email
// address corresponds to an active Google account with a calendar.
func CheckGoogleCalendar(ctx context.Context, email string, pURL *url.URL) bool {
	// Guard: extract domain and verify it uses Google MX before probing.
	// Running this probe against non-Google domains produces meaningless 401s
	// that the scoring engine would misinterpret as proof of existence.
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	domain := parts[1]

	if !CheckGoogleWorkspace(ctx, domain) {
		return false
	}

	target := fmt.Sprintf("https://calendar.google.com/calendar/dav/%s/events", email)

	for attempt := 1; attempt <= 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			return false
		}
		req.Header.Set("User-Agent", getRandomUserAgent())

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
			return false
		}

		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			resp.Body.Close()
			if attempt == 1 {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return false
		}

		// Only 200 is a genuine positive: the calendar is publicly accessible,
		// which is unusual enough to be a reliable existence signal.
		//
		// 401 is explicitly excluded. On Google CalDAV, 401 means "you need to
		// authenticate" — Google returns this for every unauthenticated request
		// regardless of whether the target address exists or has a calendar.
		// Treating 401 as a positive was the root cause of false-positive scores
		// on catch-all domains routed through non-Google MX providers.
		isOk := resp.StatusCode == 200
		resp.Body.Close()
		return isOk
	}
	return false
}

func CheckSharePoint(ctx context.Context, email string, pURL *url.URL) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	user := strings.ReplaceAll(parts[0], ".", "_")
	user = strings.ReplaceAll(user, "-", "_")
	domain := parts[1]

	domainParts := strings.Split(domain, ".")
	if len(domainParts) < 2 {
		return false
	}

	baseTenant := domainParts[0]
	userPath := fmt.Sprintf("%s_%s", user, strings.ReplaceAll(domain, ".", "_"))
	target := fmt.Sprintf("https://%s-my.sharepoint.com/personal/%s", baseTenant, userPath)

	for attempt := 1; attempt <= 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			return false
		}
		req.Header.Set("User-Agent", getRandomUserAgent())

		currentProxy := pURL
		if attempt == 2 {
			currentProxy = nil
		}

		resp, err := doProxiedNoRedirectRequest(req, currentProxy)
		if err != nil {
			if attempt == 1 {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			log.Printf("[DEBUG-OSINT] SharePoint HTTP Error for %s: %v", email, err)
			return false
		}

		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			resp.Body.Close()
			if attempt == 1 {
				time.Sleep(1 * time.Second)
				continue
			}
			return false
		}

		log.Printf("[DEBUG-OSINT] SharePoint returned Status %d for %s", resp.StatusCode, email)
		isOk := resp.StatusCode == 403 || resp.StatusCode == 401 || resp.StatusCode == 200 || resp.StatusCode == 302
		resp.Body.Close()
		return isOk
	}
	return false
}

func CheckGravatar(ctx context.Context, email string, pURL *url.URL) bool {
	cleanEmail := strings.TrimSpace(strings.ToLower(email))
	hash := md5.Sum([]byte(cleanEmail))
	hashString := fmt.Sprintf("%x", hash)
	target := fmt.Sprintf("https://www.gravatar.com/avatar/%s?d=404", hashString)

	for attempt := 1; attempt <= 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			return false
		}
		req.Header.Set("User-Agent", getRandomUserAgent())

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
			return false
		}

		if resp.StatusCode == 403 || resp.StatusCode == 429 || resp.StatusCode >= 500 {
			resp.Body.Close()
			if attempt == 1 {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return false
		}

		isOk := resp.StatusCode == 200
		resp.Body.Close()
		return isOk
	}
	return false
}

func CheckGitHub(ctx context.Context, email string, pURL *url.URL) bool {
	target := fmt.Sprintf("https://api.github.com/search/users?q=%s+in:email", email)

	for attempt := 1; attempt <= 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			return false
		}
		req.Header.Set("User-Agent", getRandomUserAgent())

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
			return false
		}

		if resp.StatusCode == 403 || resp.StatusCode == 429 || resp.StatusCode >= 500 {
			resp.Body.Close()
			if attempt == 1 {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return false
		}

		if resp.StatusCode == 200 {
			var result struct {
				TotalCount int `json:"total_count"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
				resp.Body.Close()
				return result.TotalCount > 0
			}
		}
		resp.Body.Close()
		return false
	}
	return false
}

// CheckMicrosoftLogin probes the Office 365 Autodiscover endpoint to determine
// whether an email address has an active Microsoft identity.
//
// Previously this function managed proxy.Semaphore manually without a defer,
// which could permanently leak a slot on any early return or panic. It now
// routes through doProxiedNoRedirectRequest which handles acquire/release
// correctly via defer — no manual semaphore management at this call site.
func CheckMicrosoftLogin(ctx context.Context, email string, pURL *url.URL) bool {
	targetURL := fmt.Sprintf(
		"https://outlook.office365.com/autodiscover/autodiscover.json?Email=%s&Protocol=Autodiscoverv1",
		url.QueryEscape(email),
	)

	for attempt := 1; attempt <= 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			return false
		}
		req.Header.Set("User-Agent", getRandomUserAgent())

		currentProxy := pURL
		if attempt == 2 {
			currentProxy = nil
		}

		resp, err := doProxiedNoRedirectRequest(req, currentProxy)
		if err != nil {
			if attempt == 1 {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return false
		}

		if resp.StatusCode == 403 || resp.StatusCode == 429 || resp.StatusCode >= 500 {
			resp.Body.Close()
			if attempt == 1 {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return false
		}

		isOk := resp.StatusCode == 200
		resp.Body.Close()
		return isOk
	}
	return false
}

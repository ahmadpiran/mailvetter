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

func CheckGoogleCalendar(ctx context.Context, email string, pURL *url.URL) bool {
	url := fmt.Sprintf("https://calendar.google.com/calendar/dav/%s/events", email)

	for attempt := 1; attempt <= 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return false
		}
		req.Header.Set("User-Agent", getRandomUserAgent())

		resp, err := DoProxiedRequest(req, pURL)
		if err != nil {
			if attempt == 1 {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return false
		}

		isOk := resp.StatusCode == 401 || resp.StatusCode == 200
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
	url := fmt.Sprintf("https://%s-my.sharepoint.com/personal/%s", baseTenant, userPath)

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: sharedClient.Transport,
	}

	for attempt := 1; attempt <= 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return false
		}
		req.Header.Set("User-Agent", getRandomUserAgent())

		reqCtx := context.WithValue(ctx, proxyCtxKey, pURL)
		req = req.WithContext(reqCtx)

		if pURL != nil && proxy.Enabled() {
			select {
			case proxy.Semaphore <- struct{}{}:
			case <-ctx.Done():
				return false
			}
		}

		resp, err := client.Do(req)

		if pURL != nil && proxy.Enabled() {
			<-proxy.Semaphore
		}

		if err != nil {
			if attempt == 1 {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			log.Printf("[DEBUG-OSINT] SharePoint HTTP Error for %s: %v", email, err)
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
	url := fmt.Sprintf("https://www.gravatar.com/avatar/%s?d=404", hashString)

	for attempt := 1; attempt <= 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return false
		}
		req.Header.Set("User-Agent", getRandomUserAgent())

		resp, err := DoProxiedRequest(req, pURL)
		if err != nil {
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
	url := fmt.Sprintf("https://api.github.com/search/users?q=%s+in:email", email)

	for attempt := 1; attempt <= 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return false
		}
		req.Header.Set("User-Agent", getRandomUserAgent())

		resp, err := DoProxiedRequest(req, pURL)
		if err != nil {
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

func CheckMicrosoftLogin(ctx context.Context, email string, pURL *url.URL) bool {
	targetURL := fmt.Sprintf("https://outlook.office365.com/autodiscover/autodiscover.json?Email=%s&Protocol=Autodiscoverv1", url.QueryEscape(email))

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: sharedClient.Transport,
	}

	for attempt := 1; attempt <= 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			return false
		}
		req.Header.Set("User-Agent", getRandomUserAgent())

		reqCtx := context.WithValue(req.Context(), proxyCtxKey, pURL)
		req = req.WithContext(reqCtx)

		if pURL != nil && proxy.Enabled() {
			select {
			case proxy.Semaphore <- struct{}{}:
			case <-ctx.Done():
				return false
			}
		}

		resp, err := client.Do(req)

		if pURL != nil && proxy.Enabled() {
			<-proxy.Semaphore
		}

		if err != nil {
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

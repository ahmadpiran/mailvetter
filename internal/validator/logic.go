package validator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"mailvetter/internal/cache"
	"mailvetter/internal/lookup"
	"mailvetter/internal/models"
)

// DomainResult holds the cached infrastructure data for a domain
type DomainResult struct {
	Provider      string
	HasSPF        bool
	HasDMARC      bool
	HasSaaSTokens bool
	DomainAge     int
}

// SmtpHostResult holds cached behavior of a specific MX host
type SmtpHostResult struct {
	IsCatchAll         bool
	IsPostmasterBroken bool
}

func VerifyEmail(ctx context.Context, email, domain string) (models.ValidationResult, error) {
	analysis := models.RiskAnalysis{}
	result := models.ValidationResult{Email: email}
	var mu sync.Mutex

	if lookup.IsDisposableDomain(domain) {
		result.Status = models.StatusInvalid
		result.Score = 0
		result.Reachability = models.ReachabilityBad
		return result, nil
	}

	if lookup.IsRoleAccount(email) {
		analysis.IsRoleAccount = true
	}

	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		analysis.EntropyScore = lookup.CalculateEntropy(parts[0])
	}

	var wg sync.WaitGroup

	// --- Collector A: Infra (With Caching) ---
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("[DEBUG] Collector A (Infra) STARTED for %s", domain)
		defer log.Printf("[DEBUG] Collector A (Infra) DONE for %s", domain)

		// 1. Check Cache
		cacheKey := "infra:" + domain
		if cached, ok := cache.DomainCache.Get(cacheKey); ok {
			// Cache Hit!
			d := cached.(DomainResult)
			mu.Lock()
			analysis.MxProvider = d.Provider
			analysis.HasSPF = d.HasSPF
			analysis.HasDMARC = d.HasDMARC
			analysis.HasSaaSTokens = d.HasSaaSTokens
			analysis.DomainAgeDays = d.DomainAge
			mu.Unlock()
			return
		}

		// 2. Cache Miss - Execute Network Calls
		provider, _ := lookup.IdentifyProvider(ctx, domain)
		if provider == "unknown" {
			provider = "generic"
		}

		res := DomainResult{
			Provider:      provider,
			HasSPF:        lookup.CheckSPF(ctx, domain),
			HasDMARC:      lookup.CheckDMARC(ctx, domain),
			HasSaaSTokens: lookup.CheckSaaSTokens(ctx, domain),
			DomainAge:     lookup.CheckDomainAge(ctx, domain),
		}

		// Save to Cache (15 Minutes)
		cache.DomainCache.Set(cacheKey, res, 15*time.Minute)

		mu.Lock()
		analysis.MxProvider = res.Provider
		analysis.HasSPF = res.HasSPF
		analysis.HasDMARC = res.HasDMARC
		analysis.HasSaaSTokens = res.HasSaaSTokens
		analysis.DomainAgeDays = res.DomainAge
		mu.Unlock()
	}()

	// --- Collector B: SMTP & Protocols (With Caching) ---
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("[DEBUG] Collector B (SMTP) STARTED for %s", domain)
		defer log.Printf("[DEBUG] Collector B (SMTP) DONE for %s", domain)

		// DNS Lookup is fast, but we could cache MX IPs too if needed.
		// For now, we stick to standard lookup.
		mxRecords, err := lookup.CheckDNS(ctx, domain)
		if err != nil || len(mxRecords) == 0 {
			analysis.SmtpStatus = 0
			return
		}
		sort.Slice(mxRecords, func(i, j int) bool { return mxRecords[i].Pref < mxRecords[j].Pref })
		primaryMX := mxRecords[0].Host

		// 1. VRFY
		if lookup.CheckVRFY(ctx, primaryMX, email) {
			mu.Lock()
			analysis.HasVRFY = true
			analysis.SmtpStatus = 250
			mu.Unlock()
			return
		}

		// 2. Check Cached Server Behavior
		hostCacheKey := "smtp_host:" + primaryMX + ":" + domain
		var cachedHost SmtpHostResult
		hostCached := false

		if val, ok := cache.DomainCache.Get(hostCacheKey); ok {
			cachedHost = val.(SmtpHostResult)
			hostCached = true
			mu.Lock()
			analysis.IsPostmasterBroken = cachedHost.IsPostmasterBroken
			analysis.IsCatchAll = cachedHost.IsCatchAll // Note: We still run probes to check THIS user, but we know context
			mu.Unlock()
		} else {
			// Cache Miss: Check Postmaster
			isBroken := !lookup.CheckPostmaster(ctx, primaryMX, domain)

			// Note: We don't know Catch-All status until we run probes below.
			// We will update the cache at the end of this block.
			cachedHost.IsPostmasterBroken = isBroken
			mu.Lock()
			analysis.IsPostmasterBroken = isBroken
			mu.Unlock()
		}

		// 3. Run Standard Probes (Target + Ghost)
		// Even if we know it's a catch-all domain, we run the probe to get timing data
		// and to confirm the server is reachable right now.
		status, delta, isCatchAll := runSmtpProbes(ctx, email, domain, primaryMX)

		if isCatchAll && delta > 1500 {
			// 🛑 ANTI-JITTER SAFETY RAIL: Massive delta detected.
			// We must double-check to ensure this wasn't a slow proxy connection.
			time.Sleep(1 * time.Second)
			status2, delta2, _ := runSmtpProbes(ctx, email, domain, primaryMX)

			// We take the MINIMUM delta. If the first was 11s (proxy lag) and the
			// second is 0.2s, the server is NOT tarpitting, it was just our proxy.
			if delta2 < delta {
				delta = delta2
			}
			status = status2

		} else if isCatchAll && delta > 100 && delta < 400 {
			// Existing small jitter smoother for micro-deltas
			time.Sleep(250 * time.Millisecond)
			status2, delta2, _ := runSmtpProbes(ctx, email, domain, primaryMX)
			delta = (delta + delta2) / 2
			status = status2
		}

		// Update Cache with Catch-All status if we didn't have it
		if !hostCached {
			cachedHost.IsCatchAll = isCatchAll
			// Save Cache (30 Minutes - Server config rarely changes)
			cache.DomainCache.Set(hostCacheKey, cachedHost, 30*time.Minute)
		}

		mu.Lock()
		analysis.SmtpStatus = status
		analysis.TimingDeltaMs = delta
		analysis.IsCatchAll = isCatchAll // Trust current probe
		mu.Unlock()
	}()

	// --- Collector C: Probes & History (Fully Concurrent) ---
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("[DEBUG] Collector C (Probes) STARTED for %s", email)
		defer log.Printf("[DEBUG] Collector C (Probes) DONE for %s", email)

		var probeWg sync.WaitGroup

		probeWg.Add(1)
		go func() {
			defer probeWg.Done()
			res := lookup.CheckGoogleCalendar(ctx, email)
			mu.Lock()
			analysis.HasGoogleCalendar = res
			mu.Unlock()
		}()

		probeWg.Add(1)
		go func() {
			defer probeWg.Done()
			res := lookup.CheckTeamsPresence(ctx, email, domain)
			mu.Lock()
			analysis.HasTeamsPresence = res
			mu.Unlock()
		}()

		probeWg.Add(1)
		go func() {
			defer probeWg.Done()
			res := lookup.CheckSharePoint(ctx, email)
			mu.Lock()
			analysis.HasSharePoint = res
			mu.Unlock()
		}()

		probeWg.Add(1)
		go func() {
			defer probeWg.Done()
			res := lookup.CheckAdobe(ctx, email)
			mu.Lock()
			analysis.HasAdobe = res
			mu.Unlock()
		}()

		probeWg.Add(1)
		go func() {
			defer probeWg.Done()
			res := lookup.CheckGravatar(ctx, email)
			mu.Lock()
			analysis.HasGravatar = res
			mu.Unlock()
		}()

		probeWg.Add(1)
		go func() {
			defer probeWg.Done()
			res := lookup.CheckGitHub(ctx, email)
			mu.Lock()
			analysis.HasGitHub = res
			mu.Unlock()
		}()

		apiKey := os.Getenv("HIBP_API_KEY")
		if apiKey != "" {
			probeWg.Add(1)
			go func() {
				defer probeWg.Done()
				res := lookup.CheckHIBP(ctx, email, apiKey)
				mu.Lock()
				analysis.BreachCount = res
				mu.Unlock()
			}()
		}

		// Wait for all sub-probes to finish
		probeWg.Wait()
	}()

	wg.Wait()

	finalScore, breakdown, reachability, status := CalculateRobustScore(analysis)

	result.Score = finalScore
	result.ScoreBreakdown = breakdown
	result.Reachability = reachability
	result.Status = status
	result.Analysis = analysis

	if result.Score == 0 && result.Status == models.StatusUnknown {
		result.Error = "Connection failed or no signals found"
	}

	return result, nil
}

func runSmtpProbes(ctx context.Context, email, domain, primaryMX string) (int, int64, bool) {
	randomUser := generateRandomString(12)
	ghostEmail := randomUser + "@" + domain

	var ghostTime, targetTime time.Duration
	var ghostValid, targetValid bool
	var targetErr, ghostErr error

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		targetValid, targetTime, targetErr = lookup.CheckSMTP(ctx, primaryMX, email)
	}()

	go func() {
		defer wg.Done()
		ghostValid, ghostTime, ghostErr = lookup.CheckSMTP(ctx, primaryMX, ghostEmail)
	}()

	wg.Wait()

	delta := int64(0)
	if ghostTime > 0 && targetTime > 0 {
		d := float64(ghostTime.Milliseconds()) - float64(targetTime.Milliseconds())
		delta = int64(math.Abs(d))
	}

	status := 0
	isCatchAll := false

	ghostHardBounced := !ghostValid && lookup.IsNoSuchUserError(ghostErr)

	if ghostHardBounced && targetValid {
		status = 250 // Valid
	} else if !targetValid && lookup.IsNoSuchUserError(targetErr) {
		status = 550 // Invalid
	} else if targetValid {
		status = 0
		isCatchAll = true
	}

	return status, delta, isCatchAll
}

func generateRandomString(n int) string {
	b := make([]byte, n/2)
	if _, err := rand.Read(b); err != nil {
		return "ghostuser123"
	}
	return hex.EncodeToString(b)
}

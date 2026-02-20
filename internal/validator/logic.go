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

type DomainResult struct {
	Provider      string
	HasSPF        bool
	HasDMARC      bool
	HasSaaSTokens bool
	DomainAge     int
}

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

	// --- Collector A: Infra ---
	wg.Add(1)
	go func() {
		defer wg.Done()

		cacheKey := "infra:" + domain
		if cached, ok := cache.DomainCache.Get(cacheKey); ok {
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

		cache.DomainCache.Set(cacheKey, res, 15*time.Minute)

		mu.Lock()
		analysis.MxProvider = res.Provider
		analysis.HasSPF = res.HasSPF
		analysis.HasDMARC = res.HasDMARC
		analysis.HasSaaSTokens = res.HasSaaSTokens
		analysis.DomainAgeDays = res.DomainAge
		mu.Unlock()
	}()

	// --- Collector B: SMTP & Protocols ---
	wg.Add(1)
	go func() {
		defer wg.Done()

		mxRecords, err := lookup.CheckDNS(ctx, domain)
		if err != nil || len(mxRecords) == 0 {
			// FIX: Guard this write with the mutex like all other analysis writes.
			// Without it, -race flags a data race against the reads that happen
			// in CalculateRobustScore after the outer wg.Wait() returns.
			mu.Lock()
			analysis.SmtpStatus = 0
			mu.Unlock()
			return
		}
		sort.Slice(mxRecords, func(i, j int) bool { return mxRecords[i].Pref < mxRecords[j].Pref })
		primaryMX := mxRecords[0].Host

		if lookup.CheckVRFY(ctx, primaryMX, email) {
			mu.Lock()
			analysis.HasVRFY = true
			analysis.SmtpStatus = 250
			mu.Unlock()
			return
		}

		hostCacheKey := "smtp_host:" + primaryMX + ":" + domain
		var cachedHost SmtpHostResult
		hostCached := false
		isBroken := false

		if val, ok := cache.DomainCache.Get(hostCacheKey); ok {
			cachedHost = val.(SmtpHostResult)
			hostCached = true
		} else {
			isBroken = !lookup.CheckPostmaster(ctx, primaryMX, domain)
			cachedHost.IsPostmasterBroken = isBroken
		}

		status, delta, isCatchAll := runSmtpProbes(ctx, email, domain, primaryMX)

		// FIX: Use a context-aware sleep so a tight deadline isn't held up for
		// 250ms waiting on a jitter re-probe that will be discarded anyway.
		// If the context expires during the pause we proceed with the values we
		// already have rather than blocking or returning empty results.
		if isCatchAll && delta > 100 && delta < 400 {
			select {
			case <-time.After(250 * time.Millisecond):
				status2, delta2, _ := runSmtpProbes(ctx, email, domain, primaryMX)
				delta = (delta + delta2) / 2
				status = status2
			case <-ctx.Done():
				// Proceed with current values; finalize block below handles the rest.
			}
		}

		if !hostCached {
			cachedHost.IsCatchAll = isCatchAll
			cache.DomainCache.Set(hostCacheKey, cachedHost, 30*time.Minute)
		}

		// Never overwrite live Catch-All status with cached data.
		// Only use the cache for IsPostmasterBroken, which doesn't change per-email.
		mu.Lock()
		if hostCached {
			analysis.IsPostmasterBroken = cachedHost.IsPostmasterBroken
		} else {
			analysis.IsPostmasterBroken = isBroken
		}
		analysis.IsCatchAll = isCatchAll // Always trust the live probe
		analysis.SmtpStatus = status
		analysis.TimingDeltaMs = delta
		mu.Unlock()
	}()

	// --- Collector C: Probes & History ---
	wg.Add(1)
	go func() {
		defer wg.Done()

		var hasGCal, hasTeams, hasSharePoint, hasAdobe, hasGravatar, hasGitHub bool
		var breachCount int
		var probeWg sync.WaitGroup

		probeWg.Add(1)
		go func() {
			defer probeWg.Done()
			if lookup.CheckGoogleCalendar(ctx, email) {
				mu.Lock()
				hasGCal = true
				mu.Unlock()
			}
		}()

		probeWg.Add(1)
		go func() {
			defer probeWg.Done()
			if lookup.CheckTeamsPresence(ctx, email, domain) {
				mu.Lock()
				hasTeams = true
				mu.Unlock()
			}
		}()

		probeWg.Add(1)
		go func() {
			defer probeWg.Done()
			if lookup.CheckSharePoint(ctx, email) {
				mu.Lock()
				hasSharePoint = true
				mu.Unlock()
			}
		}()

		probeWg.Add(1)
		go func() {
			defer probeWg.Done()
			if lookup.CheckAdobe(ctx, email) {
				mu.Lock()
				hasAdobe = true
				mu.Unlock()
			}
		}()

		probeWg.Add(1)
		go func() {
			defer probeWg.Done()
			if lookup.CheckGravatar(ctx, email) {
				mu.Lock()
				hasGravatar = true
				mu.Unlock()
			}
		}()

		probeWg.Add(1)
		go func() {
			defer probeWg.Done()
			if lookup.CheckGitHub(ctx, email) {
				mu.Lock()
				hasGitHub = true
				mu.Unlock()
			}
		}()

		apiKey := os.Getenv("HIBP_API_KEY")
		if apiKey != "" {
			probeWg.Add(1)
			go func() {
				defer probeWg.Done()
				bc := lookup.CheckHIBP(ctx, email, apiKey)
				mu.Lock()
				breachCount = bc
				mu.Unlock()
			}()
		}

		// Context-Aware WaitGroup for OSINT probes
		c := make(chan struct{})
		go func() {
			defer close(c)
			probeWg.Wait()
		}()

		select {
		case <-c:
			mu.Lock()
			analysis.HasGoogleCalendar = hasGCal
			analysis.HasTeamsPresence = hasTeams
			analysis.HasSharePoint = hasSharePoint
			analysis.HasAdobe = hasAdobe
			analysis.HasGravatar = hasGravatar
			analysis.HasGitHub = hasGitHub
			analysis.BreachCount = breachCount
			mu.Unlock()
		case <-ctx.Done():
			// Safely abort if the worker context expires
			return
		}
	}()

	// Context-Aware WaitGroup for the main collectors
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()

	select {
	case <-c:
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

	case <-ctx.Done():
		result.Status = models.StatusUnknown
		result.Error = "Validation timed out due to slow proxy or unresponsive server"
		return result, ctx.Err()
	}
}

func runSmtpProbes(ctx context.Context, email, domain, primaryMX string) (int, int64, bool) {
	randomUser := generateRandomString(12)
	ghostEmail := randomUser + "@" + domain

	var targetValid, ghostValid bool
	var targetTime, ghostTime time.Duration
	var targetErr, ghostErr error

	for attempt := 1; attempt <= 2; attempt++ {
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

		// Context-Aware WaitGroup for SMTP network calls
		c := make(chan struct{})
		go func() {
			defer close(c)
			wg.Wait()
		}()

		select {
		case <-c:
			// Normal completion
		case <-ctx.Done():
			return 0, 0, false
		}

		targetTransient := !targetValid && targetErr != nil && !lookup.IsNoSuchUserError(targetErr)
		ghostTransient := !ghostValid && ghostErr != nil && !lookup.IsNoSuchUserError(ghostErr)

		if !targetTransient && !ghostTransient {
			break
		}

		if attempt == 1 {
			log.Printf("[DEBUG] Transient error via proxy for %s, retrying...", email)
			// Context-aware sleep. If the timeout fires during the 2-second pause
			// we abort instantly rather than burning the remaining deadline.
			select {
			case <-time.After(2 * time.Second):
				// Sleep finished, proceed to attempt 2
			case <-ctx.Done():
				return 0, 0, false
			}
		}
	}

	delta := int64(0)
	if ghostTime > 0 && targetTime > 0 {
		d := float64(ghostTime.Milliseconds()) - float64(targetTime.Milliseconds())
		delta = int64(math.Abs(d))
	}

	targetTransient := !targetValid && targetErr != nil && !lookup.IsNoSuchUserError(targetErr)
	ghostTransient := !ghostValid && ghostErr != nil && !lookup.IsNoSuchUserError(ghostErr)

	if targetTransient || ghostTransient {
		return 0, 0, false
	}

	status := 0
	isCatchAll := false

	ghostHardBounced := !ghostValid && lookup.IsNoSuchUserError(ghostErr)

	if ghostHardBounced && targetValid {
		status = 250
	} else if !targetValid && lookup.IsNoSuchUserError(targetErr) {
		status = 550
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

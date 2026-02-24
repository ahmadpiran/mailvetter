package validator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"math"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"mailvetter/internal/cache"
	"mailvetter/internal/lookup"
	"mailvetter/internal/models"
	"mailvetter/internal/proxy"
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

	var pinnedProxy *url.URL
	if proxy.Enabled() {
		pinnedProxy = proxy.Global.Next()
	}

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
			DomainAge:     lookup.CheckDomainAge(ctx, domain, pinnedProxy),
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

	wg.Add(1)
	go func() {
		defer wg.Done()

		mxRecords, err := lookup.CheckDNS(ctx, domain)
		if err != nil || len(mxRecords) == 0 {
			mu.Lock()
			analysis.SmtpStatus = 0
			mu.Unlock()
			return
		}
		sort.Slice(mxRecords, func(i, j int) bool { return mxRecords[i].Pref < mxRecords[j].Pref })
		primaryMX := mxRecords[0].Host

		if lookup.CheckVRFY(ctx, primaryMX, email, pinnedProxy) {
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
			isBroken = !lookup.CheckPostmaster(ctx, primaryMX, domain, pinnedProxy)
			cachedHost.IsPostmasterBroken = isBroken
		}

		if !hostCached {
			time.Sleep(500 * time.Millisecond)
		}

		status, delta, isCatchAll := runSmtpProbes(ctx, email, domain, primaryMX, pinnedProxy)

		if isCatchAll && delta > 100 && delta < 400 {
			select {
			case <-time.After(250 * time.Millisecond):
				status2, delta2, _ := runSmtpProbes(ctx, email, domain, primaryMX, pinnedProxy)
				delta = (delta + delta2) / 2
				status = status2
			case <-ctx.Done():
			}
		}

		if !hostCached {
			cachedHost.IsCatchAll = isCatchAll
			cache.DomainCache.Set(hostCacheKey, cachedHost, 30*time.Minute)
		}

		mu.Lock()
		if hostCached {
			analysis.IsPostmasterBroken = cachedHost.IsPostmasterBroken
		} else {
			analysis.IsPostmasterBroken = isBroken
		}
		analysis.IsCatchAll = isCatchAll
		analysis.SmtpStatus = status
		analysis.TimingDeltaMs = delta
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		var hasGCal, hasTeams, hasSharePoint, hasAdobe, hasGravatar, hasGitHub bool
		var breachCount int
		var probeWg sync.WaitGroup

		probeWg.Add(1)
		go func() {
			defer probeWg.Done()
			if lookup.CheckGoogleCalendar(ctx, email, pinnedProxy) {
				mu.Lock()
				hasGCal = true
				mu.Unlock()
			}
		}()

		probeWg.Add(1)
		go func() {
			defer probeWg.Done()
			if lookup.CheckTeamsPresence(ctx, email, domain, pinnedProxy) {
				mu.Lock()
				hasTeams = true
				mu.Unlock()
			}
		}()

		probeWg.Add(1)
		go func() {
			defer probeWg.Done()
			if lookup.CheckSharePoint(ctx, email, pinnedProxy) {
				mu.Lock()
				hasSharePoint = true
				mu.Unlock()
			}
		}()

		probeWg.Add(1)
		go func() {
			defer probeWg.Done()
			if lookup.CheckAdobe(ctx, email, pinnedProxy) {
				mu.Lock()
				hasAdobe = true
				mu.Unlock()
			}
		}()

		probeWg.Add(1)
		go func() {
			defer probeWg.Done()
			if lookup.CheckGravatar(ctx, email, pinnedProxy) {
				mu.Lock()
				hasGravatar = true
				mu.Unlock()
			}
		}()

		probeWg.Add(1)
		go func() {
			defer probeWg.Done()
			if lookup.CheckGitHub(ctx, email, pinnedProxy) {
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
				bc := lookup.CheckHIBP(ctx, email, apiKey, pinnedProxy)
				mu.Lock()
				breachCount = bc
				mu.Unlock()
			}()
		}

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
			return
		}
	}()

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

func runSmtpProbes(ctx context.Context, email, domain, primaryMX string, pURL *url.URL) (int, int64, bool) {
	var targetValid bool
	var targetTime time.Duration
	var targetErr error

	for attempt := 1; attempt <= 2; attempt++ {
		targetValid, targetTime, targetErr = lookup.CheckSMTP(ctx, primaryMX, email, pURL)
		targetTransient := !targetValid && targetErr != nil && !lookup.IsNoSuchUserError(targetErr)

		if !targetTransient {
			break
		}

		if attempt == 1 {
			log.Printf("[DEBUG] Transient error via proxy for TARGET %s, retrying... Error: %v", email, targetErr)
			select {
			case <-time.After(2 * time.Second):
			case <-ctx.Done():
				return 0, 0, false
			}
		}
	}

	targetTransient := !targetValid && targetErr != nil && !lookup.IsNoSuchUserError(targetErr)
	if targetTransient {
		return 0, 0, false
	}

	if !targetValid && lookup.IsNoSuchUserError(targetErr) {
		log.Printf("[ERROR] Final target transient failure for %s: %v", email, targetErr)
		return 550, 0, false
	}

	time.Sleep(500 * time.Millisecond)

	randomUser := generateRandomString(12)
	ghostEmail := randomUser + "@" + domain

	var ghostValid bool
	var ghostTime time.Duration
	var ghostErr error

	for attempt := 1; attempt <= 2; attempt++ {
		ghostValid, ghostTime, ghostErr = lookup.CheckSMTP(ctx, primaryMX, ghostEmail, pURL)
		ghostTransient := !ghostValid && ghostErr != nil && !lookup.IsNoSuchUserError(ghostErr)

		if !ghostTransient {
			break
		}

		if attempt == 1 {
			log.Printf("[DEBUG] Transient error via proxy for GHOST %s, retrying...", ghostEmail)
			select {
			case <-time.After(2 * time.Second):
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

	ghostHardBounced := !ghostValid && lookup.IsNoSuchUserError(ghostErr)
	ghostTransient := !ghostValid && ghostErr != nil && !lookup.IsNoSuchUserError(ghostErr)

	status := 0
	isCatchAll := false

	if targetValid {
		if ghostHardBounced {
			status = 250
		} else if ghostValid {
			status = 0
			isCatchAll = true
		} else if ghostTransient {
			status = 250
		}
	}

	return status, delta, isCatchAll
}

func generateRandomString(_ int) string {
	firstNames := []string{"alex", "michael", "sarah", "david", "emma", "chris", "jessica", "matthew", "amanda", "daniel"}
	lastNames := []string{"smith", "jones", "taylor", "brown", "williams", "wilson", "johnson", "davis", "miller", "martin"}

	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "michael.smith.99"
	}

	fIdx := int(b[0]) % len(firstNames)
	lIdx := int(b[1]) % len(lastNames)

	return firstNames[fIdx] + "." + lastNames[lIdx] + "." + hex.EncodeToString(b[2:])
}

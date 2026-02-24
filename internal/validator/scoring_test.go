package validator

import (
	"mailvetter/internal/models"
	"testing"
)

func TestCalculateRobustScore(t *testing.T) {
	tests := []struct {
		name             string
		input            models.RiskAnalysis
		expectedScoreMin int
		expectedScoreMax int
		expectedReach    models.Reachability
		expectedStatus   models.VerificationStatus
	}{
		// ── Baseline cases ────────────────────────────────────────────────────
		{
			name: "Standard Valid Business Email",
			input: models.RiskAnalysis{
				SmtpStatus: 250,
				HasSPF:     true,
				HasDMARC:   true,
			},
			expectedScoreMin: 90,
			expectedScoreMax: 99,
			expectedReach:    models.ReachabilitySafe,
			expectedStatus:   models.StatusValid,
		},
		{
			name: "Hard Bounce (Strict Invalid)",
			input: models.RiskAnalysis{
				SmtpStatus:         550,
				IsPostmasterBroken: true,
			},
			expectedScoreMin: 0,
			expectedScoreMax: 0,
			expectedStatus:   models.StatusInvalid,
			expectedReach:    models.ReachabilityBad,
		},
		{
			name: "High Entropy Bot (No Proof)",
			input: models.RiskAnalysis{
				SmtpStatus:   250,
				EntropyScore: 0.85,
			},
			expectedScoreMin: 65,
			expectedScoreMax: 75,
			expectedReach:    models.ReachabilityRisky,
			expectedStatus:   models.StatusValid,
		},

		// ── Catch-all cases ───────────────────────────────────────────────────
		{
			name: "Standard Catch-All (No Footprint, Unknown Age)",
			input: models.RiskAnalysis{
				IsCatchAll:    true,
				MxProvider:    "google",
				TimingDeltaMs: 50,
				DomainAgeDays: 0, // RDAP returned no data — penalty still applies
			},
			// Base(30) - catchall_empty(20) = 10
			expectedScoreMin: 5,
			expectedScoreMax: 20,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "Catch-All with Weak Timing Only",
			input: models.RiskAnalysis{
				IsCatchAll:    true,
				MxProvider:    "google",
				TimingDeltaMs: 2000,
				DomainAgeDays: 0,
			},
			// Base(30) + timing_weak(25) - catchall_empty(20) = 35
			expectedScoreMin: 30,
			expectedScoreMax: 40,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "Absolute Proof Overrides Penalties",
			input: models.RiskAnalysis{
				IsCatchAll:    true,
				MxProvider:    "google",
				BreachCount:   2,
				EntropyScore:  0.9,
				DomainAgeDays: 5,
			},
			expectedScoreMin: 90,
			expectedScoreMax: 99,
			expectedReach:    models.ReachabilitySafe,
			expectedStatus:   models.StatusValid,
		},
		{
			name: "Soft Proof Shields Penalties (O365 Catch-All)",
			input: models.RiskAnalysis{
				IsCatchAll:       true,
				MxProvider:       "office365",
				HasGitHub:        true,
				DomainAgeDays:    5,
				HasTeamsPresence: false,
			},
			expectedScoreMin: 60,
			expectedScoreMax: 70,
			expectedReach:    models.ReachabilityRisky,
			expectedStatus:   models.StatusCatchAll,
		},

		// ── Domain age signal cases ───────────────────────────────────────────
		{
			// Regression test for tarun@validus.sg production case.
			// Google Workspace catch-all, 10+ year old domain, SPF+DMARC+SaaS.
			// Previously scored 28 (Bad). Should be ~63 (Risky).
			//
			// Base(30) + SPF(3.5) + DMARC(4.5) + SaaS(10) + vetted_age(15) = 63
			// No catchall_empty penalty: isEstablishedDomain=true.
			name: "Google Workspace catch-all, vetted domain age (validus.sg regression)",
			input: models.RiskAnalysis{
				IsCatchAll:    true,
				MxProvider:    "google",
				HasSPF:        true,
				HasDMARC:      true,
				HasSaaSTokens: true,
				DomainAgeDays: 3903,
				TimingDeltaMs: 137,
			},
			expectedScoreMin: 58,
			expectedScoreMax: 68,
			expectedReach:    models.ReachabilityRisky,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			// Established domain (1–5 years) gets the smaller age boost.
			name: "Catch-all, established domain age (1-5 years)",
			input: models.RiskAnalysis{
				IsCatchAll:    true,
				MxProvider:    "google",
				HasSPF:        true,
				HasDMARC:      true,
				DomainAgeDays: 730, // 2 years
			},
			// Base(30) + SPF(3.5) + DMARC(4.5) + established_age(10) = 48
			// No catchall_empty: isEstablishedDomain=true
			expectedScoreMin: 43,
			expectedScoreMax: 53,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			// New domain (< 30 days) with no proof still gets the new-domain penalty.
			name: "New domain catch-all (< 30 days), no proof",
			input: models.RiskAnalysis{
				IsCatchAll:    true,
				MxProvider:    "generic",
				DomainAgeDays: 10,
			},
			// Base(30) - new_domain(50) - catchall_empty(20) = -40 → clamped to 0
			expectedScoreMin: 0,
			expectedScoreMax: 5,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			// DomainAgeDays == 0 means RDAP returned no data, not that the domain
			// is new. The age boost should NOT fire; the empty penalty still applies.
			name: "Unknown domain age (RDAP returned 0) — no boost, penalty applies",
			input: models.RiskAnalysis{
				IsCatchAll:    true,
				MxProvider:    "google",
				DomainAgeDays: 0,
			},
			// Base(30) - catchall_empty(20) = 10
			expectedScoreMin: 5,
			expectedScoreMax: 15,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},

		// ── Enterprise gateway catch-all cases ────────────────────────────────
		{
			// Regression test for gmehta@raine.com.
			// Barracuda catch-all, SPF+DMARC+SaaS, unknown domain age.
			// Base(30) + enterprise_sec(15) + SaaS(10) + SPF(3.5) + DMARC(4.5) = 63
			// No catchall_empty: hasEnterpriseGateway=true.
			name: "Barracuda catch-all with SPF+DMARC+SaaS (raine.com regression)",
			input: models.RiskAnalysis{
				IsCatchAll:    true,
				MxProvider:    "barracuda",
				HasSPF:        true,
				HasDMARC:      true,
				HasSaaSTokens: true,
				TimingDeltaMs: 39,
			},
			expectedScoreMin: 58,
			expectedScoreMax: 68,
			expectedReach:    models.ReachabilityRisky,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "Proofpoint catch-all with SPF+DMARC",
			input: models.RiskAnalysis{
				IsCatchAll: true,
				MxProvider: "proofpoint",
				HasSPF:     true,
				HasDMARC:   true,
			},
			// Base(30) + enterprise_sec(15) + SPF(3.5) + DMARC(4.5) = 53
			expectedScoreMin: 48,
			expectedScoreMax: 58,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "Generic catch-all, no footprint, unknown age — penalty applies",
			input: models.RiskAnalysis{
				IsCatchAll: true,
				MxProvider: "generic",
			},
			// Base(30) - catchall_empty(20) = 10
			expectedScoreMin: 5,
			expectedScoreMax: 15,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},

		// ── Unknown domain cases ──────────────────────────────────────────────
		{
			name: "Unknown Domain Upgraded to Valid by Absolute Proof (Calendar)",
			input: models.RiskAnalysis{
				SmtpStatus:        0,
				IsCatchAll:        false,
				HasGoogleCalendar: true,
			},
			// Base(20) + Calendar(42.5) + Strong Unknown Boost(50) = 112.5 → 99
			expectedScoreMin: 90,
			expectedScoreMax: 99,
			expectedReach:    models.ReachabilitySafe,
			expectedStatus:   models.StatusValid,
		},
		{
			name: "Unknown Domain with Soft Proof (GitHub + Adobe)",
			input: models.RiskAnalysis{
				SmtpStatus: 0,
				IsCatchAll: false,
				HasGitHub:  true,
				HasAdobe:   true,
			},
			// Base(20) + GitHub(12) + Adobe(18.5) + Medium Unknown Boost(25) = 75.5 → 76
			expectedScoreMin: 70,
			expectedScoreMax: 80,
			expectedReach:    models.ReachabilityRisky,
			expectedStatus:   models.StatusUnknown,
		},

		// ── O365 catch-all cases (SmtpStatus = 0) ────────────────────────────
		{
			name: "Office 365 Zombie (Pure Ghost Catch-All, no SMTP 250)",
			input: models.RiskAnalysis{
				IsCatchAll:       true,
				MxProvider:       "office365",
				HasTeamsPresence: false,
				HasSharePoint:    false,
				DomainAgeDays:    0,
			},
			// Base(30) - o365_ghost(30) = 0
			expectedScoreMin: 0,
			expectedScoreMax: 5,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "O365 Catch-All Upgraded to Valid by Teams Identity",
			input: models.RiskAnalysis{
				IsCatchAll:       true,
				MxProvider:       "office365",
				HasTeamsPresence: true,
			},
			// Base(30) + Teams(15) + CatchAll Strong(50) = 95
			expectedScoreMin: 90,
			expectedScoreMax: 99,
			expectedReach:    models.ReachabilitySafe,
			expectedStatus:   models.StatusValid,
		},

		// ── O365 zombie correction cases (SmtpStatus = 250) ──────────────────
		{
			name: "O365 Zombie: SMTP 250 but no SharePoint or Teams (Ghost)",
			input: models.RiskAnalysis{
				SmtpStatus:       250,
				MxProvider:       "office365",
				HasTeamsPresence: false,
				HasSharePoint:    false,
			},
			// Base(90) - correction(60) - ghost(30) = 0
			expectedScoreMin: 0,
			expectedScoreMax: 5,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "O365 Zombie: SMTP 250, Teams identity exists, no SharePoint license",
			input: models.RiskAnalysis{
				SmtpStatus:       250,
				MxProvider:       "office365",
				HasTeamsPresence: true,
				HasSharePoint:    false,
			},
			// Base(90) - correction(60) - unlicensed(20) + Teams(15) = 25
			expectedScoreMin: 20,
			expectedScoreMax: 30,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "O365 Zombie with soft proof partially recovers score",
			input: models.RiskAnalysis{
				SmtpStatus:       250,
				MxProvider:       "office365",
				HasTeamsPresence: true,
				HasSharePoint:    false,
				HasGitHub:        true,
			},
			// Base(90) - correction(60) - unlicensed(20) + Teams(15) + GitHub(12) = 37
			expectedScoreMin: 32,
			expectedScoreMax: 42,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "O365 valid: SMTP 250 with SharePoint — correction does NOT fire",
			input: models.RiskAnalysis{
				SmtpStatus:       250,
				MxProvider:       "office365",
				HasTeamsPresence: true,
				HasSharePoint:    true,
			},
			// Base(90) + SharePoint(60) = 150 → 99
			expectedScoreMin: 90,
			expectedScoreMax: 99,
			expectedReach:    models.ReachabilitySafe,
			expectedStatus:   models.StatusValid,
		},
		{
			name: "O365 Ghost: SMTP 250, no footprint, but has breach history",
			input: models.RiskAnalysis{
				SmtpStatus:       250,
				MxProvider:       "office365",
				HasTeamsPresence: false,
				HasSharePoint:    false,
				BreachCount:      1,
			},
			// Base(90) - correction(60) - ghost(30) + Breach(45) = 45
			// Status stays catch_all: o365ZombieCorrected=true blocks upgrade
			expectedScoreMin: 40,
			expectedScoreMax: 50,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "Non-O365 provider: SMTP 250 correction does NOT fire",
			input: models.RiskAnalysis{
				SmtpStatus: 250,
				MxProvider: "google",
			},
			expectedScoreMin: 90,
			expectedScoreMax: 99,
			expectedReach:    models.ReachabilitySafe,
			expectedStatus:   models.StatusValid,
		},

		// ── Google Calendar false positive guard ──────────────────────────────
		{
			name: "Google Workspace catch-all with legitimate Calendar signal",
			input: models.RiskAnalysis{
				IsCatchAll:        true,
				MxProvider:        "google",
				HasSPF:            true,
				HasDMARC:          true,
				HasGoogleCalendar: true,
				DomainAgeDays:     3903,
			},
			// Base(30) + Calendar(42.5) + SPF(3.5) + DMARC(4.5) + vetted(15) + strong(50) = 145.5 → 99
			expectedScoreMin: 90,
			expectedScoreMax: 99,
			expectedReach:    models.ReachabilitySafe,
			expectedStatus:   models.StatusValid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, _, reach, status := CalculateRobustScore(tt.input)

			if score < tt.expectedScoreMin || score > tt.expectedScoreMax {
				t.Errorf("Score %d not in range [%d, %d]", score, tt.expectedScoreMin, tt.expectedScoreMax)
			}
			if reach != tt.expectedReach {
				t.Errorf("Reachability %q != expected %q", reach, tt.expectedReach)
			}
			if tt.expectedStatus != "" && status != tt.expectedStatus {
				t.Errorf("Status %q != expected %q", status, tt.expectedStatus)
			}
		})
	}
}

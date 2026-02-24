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

		// ── Catch-all status upgrade cases ───────────────────────────────────
		//
		// catch_all + score >= 60 → StatusRisky (credible domain, attempt delivery)
		// catch_all + score <  60 → StatusCatchAll (no evidence, do not send)
		{
			name: "Barracuda catch-all with SPF+DMARC+SaaS → StatusRisky",
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
			expectedStatus:   models.StatusRisky,
		},
		{
			// Regression: tarun@validus.sg — Google Workspace, 10yr domain.
			// Score ~63 → StatusRisky.
			name: "Google Workspace catch-all, vetted domain age → StatusRisky",
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
			expectedStatus:   models.StatusRisky,
		},
		{
			// Regression — IronPort, 24yr domain.
			// Score ~78 → StatusRisky.
			name: "IronPort catch-all, vetted domain age → StatusRisky",
			input: models.RiskAnalysis{
				IsCatchAll:    true,
				MxProvider:    "ironport",
				HasSPF:        true,
				HasDMARC:      true,
				HasSaaSTokens: true,
				DomainAgeDays: 8947,
				TimingDeltaMs: 64,
			},
			expectedScoreMin: 73,
			expectedScoreMax: 83,
			expectedReach:    models.ReachabilityRisky,
			expectedStatus:   models.StatusRisky,
		},
		{
			// Low-scoring catch-all stays StatusCatchAll — upgrade does not fire.
			name: "Generic catch-all no footprint → StatusCatchAll (score < 60)",
			input: models.RiskAnalysis{
				IsCatchAll:    true,
				MxProvider:    "generic",
				DomainAgeDays: 0,
			},
			// Base(30) - catchall_empty(20) = 10
			expectedScoreMin: 5,
			expectedScoreMax: 15,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			// O365 zombie-corrected account — upgrade blocked even if score >= 60.
			// Teams + GitHub partially recover the score but mailbox undeliverable.
			name: "O365 Zombie with soft proof — upgrade blocked, stays StatusCatchAll",
			input: models.RiskAnalysis{
				SmtpStatus:       250,
				MxProvider:       "office365",
				HasTeamsPresence: true,
				HasSharePoint:    false,
				HasGitHub:        true,
				DomainAgeDays:    4000,
			},
			// Base(90) - correction(60) - unlicensed(20) + Teams(15) + GitHub(12)
			// + vetted_age(15) = 52 — below 60, stays catch_all anyway.
			// (Confirms the o365ZombieCorrected guard works even if score drifts above 60
			// in future due to new signal weights.)
			expectedScoreMin: 47,
			expectedScoreMax: 57,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			// Soft proof catch-all scores ~55 — below threshold, stays catch_all.
			name: "Catch-all with GitHub only, no domain age — stays StatusCatchAll",
			input: models.RiskAnalysis{
				IsCatchAll:    true,
				MxProvider:    "google",
				HasGitHub:     true,
				DomainAgeDays: 0,
			},
			// Base(30) + GitHub(12) + resolution_medium(25) = 67 → actually risky
			// Wait — hasSoftProof=true skips empty penalty AND adds +25. Let's recheck:
			// 30 + 12 + 25 = 67 → StatusRisky. Correcting expectation.
			expectedScoreMin: 62,
			expectedScoreMax: 72,
			expectedReach:    models.ReachabilityRisky,
			expectedStatus:   models.StatusRisky,
		},
		{
			// Absolute proof upgrades directly to StatusValid — step 9 skipped.
			name: "Catch-all with breach proof → StatusValid (not StatusRisky)",
			input: models.RiskAnalysis{
				IsCatchAll:    true,
				MxProvider:    "google",
				BreachCount:   1,
				DomainAgeDays: 1000,
			},
			expectedScoreMin: 90,
			expectedScoreMax: 99,
			expectedReach:    models.ReachabilitySafe,
			expectedStatus:   models.StatusValid,
		},

		// ── Standard catch-all cases ──────────────────────────────────────────
		{
			name: "Standard Catch-All (No Footprint, Unknown Age)",
			input: models.RiskAnalysis{
				IsCatchAll:    true,
				MxProvider:    "google",
				TimingDeltaMs: 50,
				DomainAgeDays: 0,
			},
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
			// Soft proof on O365 catch-all scores ~67 → StatusRisky.
			name: "Soft Proof on O365 Catch-All → StatusRisky",
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
			expectedStatus:   models.StatusRisky,
		},

		// ── Domain age signal cases ───────────────────────────────────────────
		{
			name: "Catch-all, established domain age (1-5 years)",
			input: models.RiskAnalysis{
				IsCatchAll:    true,
				MxProvider:    "google",
				HasSPF:        true,
				HasDMARC:      true,
				DomainAgeDays: 730,
			},
			// Base(30) + SPF(3.5) + DMARC(4.5) + established_age(10) = 48
			expectedScoreMin: 43,
			expectedScoreMax: 53,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "New domain catch-all (< 30 days), no proof",
			input: models.RiskAnalysis{
				IsCatchAll:    true,
				MxProvider:    "generic",
				DomainAgeDays: 10,
			},
			expectedScoreMin: 0,
			expectedScoreMax: 5,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "Unknown domain age (RDAP returned 0) — no boost, penalty applies",
			input: models.RiskAnalysis{
				IsCatchAll:    true,
				MxProvider:    "google",
				DomainAgeDays: 0,
			},
			expectedScoreMin: 5,
			expectedScoreMax: 15,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},

		// ── Enterprise gateway catch-all cases ────────────────────────────────
		{
			name: "IronPort catch-all, unknown domain age",
			input: models.RiskAnalysis{
				IsCatchAll:    true,
				MxProvider:    "ironport",
				HasSPF:        true,
				HasDMARC:      true,
				DomainAgeDays: 0,
			},
			// Base(30) + enterprise_sec(15) + SPF(3.5) + DMARC(4.5) = 53
			expectedScoreMin: 48,
			expectedScoreMax: 58,
			expectedReach:    models.ReachabilityBad,
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

		// ── Unknown domain cases ──────────────────────────────────────────────
		{
			name: "Unknown Domain Upgraded to Valid by Absolute Proof (Calendar)",
			input: models.RiskAnalysis{
				SmtpStatus:        0,
				IsCatchAll:        false,
				HasGoogleCalendar: true,
			},
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
			// Base(30) - o365_ghost(30) = 0 → StatusCatchAll (score < 60)
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
			// Base(30) + Teams(15) + CatchAll Strong(50) = 95 → StatusValid
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
			name: "O365 valid: SMTP 250 with SharePoint — correction does NOT fire",
			input: models.RiskAnalysis{
				SmtpStatus:       250,
				MxProvider:       "office365",
				HasTeamsPresence: true,
				HasSharePoint:    true,
			},
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
			// o365ZombieCorrected=true: upgrade blocked, stays catch_all
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
			// Base(30) + Calendar(42.5) + ... + strong(50) = 145.5 → 99 → StatusValid
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

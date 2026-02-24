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
			name: "Standard Catch-All (No Footprint)",
			input: models.RiskAnalysis{
				IsCatchAll:    true,
				MxProvider:    "google",
				TimingDeltaMs: 50,
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
			},
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

		// ── Enterprise gateway catch-all cases ────────────────────────────────
		{
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
			// Proofpoint catch-all — same logic, confirms Barracuda fix doesn't
			// break existing enterprise gateway behaviour.
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
			// Empty catch-all on a generic domain — penalty still applies.
			name: "Generic catch-all, no footprint, no enterprise gateway",
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
			// Base(90) - correction(60) - ghost(30) = 0
			input: models.RiskAnalysis{
				SmtpStatus:       250,
				MxProvider:       "office365",
				HasTeamsPresence: false,
				HasSharePoint:    false,
			},
			expectedScoreMin: 0,
			expectedScoreMax: 5,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "O365 Zombie: SMTP 250, Teams identity exists, no SharePoint license",
			// Base(90) - correction(60) - unlicensed(20) + Teams(15) = 25
			input: models.RiskAnalysis{
				SmtpStatus:       250,
				MxProvider:       "office365",
				HasTeamsPresence: true,
				HasSharePoint:    false,
			},
			expectedScoreMin: 20,
			expectedScoreMax: 30,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "O365 Zombie with soft proof partially recovers score",
			// Base(90) - correction(60) - unlicensed(20) + Teams(15) + GitHub(12) = 37
			input: models.RiskAnalysis{
				SmtpStatus:       250,
				MxProvider:       "office365",
				HasTeamsPresence: true,
				HasSharePoint:    false,
				HasGitHub:        true,
			},
			expectedScoreMin: 32,
			expectedScoreMax: 42,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "O365 valid: SMTP 250 with SharePoint — correction does NOT fire",
			// Base(90) + SharePoint(60) = 150 → clamped to 99
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
			// Base(90) - correction(60) - ghost(30) + Breach(45) = 45
			// Status stays catch_all despite breach (o365ZombieCorrected=true)
			input: models.RiskAnalysis{
				SmtpStatus:       250,
				MxProvider:       "office365",
				HasTeamsPresence: false,
				HasSharePoint:    false,
				BreachCount:      1,
			},
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
			// Verifies that a legitimate Google Calendar signal on a real
			// Google Workspace catch-all still produces a Safe score.
			name: "Google Workspace catch-all with legitimate Calendar signal",
			input: models.RiskAnalysis{
				IsCatchAll:        true,
				MxProvider:        "google",
				HasSPF:            true,
				HasDMARC:          true,
				HasGoogleCalendar: true,
			},
			// Base(30) + Calendar(42.5) + SPF(3.5) + DMARC(4.5) + strong(50) = 130.5 → 99
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

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

		// ── Unknown domain cases ──────────────────────────────────────────────
		{
			name: "Unknown Domain Upgraded to Valid by Absolute Proof (Calendar)",
			input: models.RiskAnalysis{
				SmtpStatus:        0,
				IsCatchAll:        false,
				HasGoogleCalendar: true,
			},
			// Base(20) + Calendar(42.5) + Strong Unknown Boost(50) = 112.5 → clamped to 99
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
		// These do NOT enter the zombie correction block (SmtpStatus != 250).
		{
			name: "Office 365 Zombie (Pure Ghost Catch-All, no SMTP 250)",
			input: models.RiskAnalysis{
				IsCatchAll:       true,
				MxProvider:       "office365",
				HasTeamsPresence: false,
				HasSharePoint:    false,
			},
			expectedScoreMin: 0,
			expectedScoreMax: 10,
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
		// These ARE the newly implemented correction paths (issue #11).
		{
			name: "O365 Zombie: SMTP 250 but no SharePoint or Teams (Ghost)",
			// SMTP lied. User has zero Microsoft footprint.
			// correction_o365_false_positive(-60) + penalty_o365_ghost(-30)
			// Base(90) - 60 - 30 = 0
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
			// Identity confirmed but mailbox unlicensed — cannot receive mail.
			// correction_o365_false_positive(-60) + penalty_o365_unlicensed(-20)
			// Base(90) - 60 - 20 + Teams(15) = 25
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
			// Unlicensed zombie who also has a GitHub account.
			// Base(90) - 60 - 20 + Teams(15) + GitHub(12) = 37
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
			// SharePoint proves an active licensed mailbox. This is a genuinely
			// deliverable address — the correction block must not touch it.
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
			// Breach history is absolute proof the address existed as a real
			// human inbox at some point. Even on a zombie O365 account the
			// breach boost partially recovers the score after correction.
			// Base(90) - 60 - 30 + Breach(45) = 45
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
			// The zombie correction is O365-specific. Google Workspace and
			// generic providers returning 250 should not be penalised.
			input: models.RiskAnalysis{
				SmtpStatus: 250,
				MxProvider: "google",
			},
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

func TestGoogleCalendarFalsePositive(t *testing.T) {
	tests := []struct {
		name             string
		input            models.RiskAnalysis
		expectedScoreMin int
		expectedScoreMax int
		expectedReach    models.Reachability
		expectedStatus   models.VerificationStatus
	}{
		{
			// Reproduces the gmehta@raine.com production case.
			// Barracuda catch-all with SPF + DMARC + SaaS tokens but no
			// social footprint and a negligible timing delta.
			// Expected: Risky, not Safe.
			name: "Barracuda catch-all, no Google Calendar, no social proof",
			input: models.RiskAnalysis{
				IsCatchAll:        true,
				MxProvider:        "barracuda",
				HasSPF:            true,
				HasDMARC:          true,
				HasSaaSTokens:     true,
				HasGoogleCalendar: false, // probe correctly returns false now
				TimingDeltaMs:     58,    // too low to be a timing signal
			},
			// Base(30) + SPF(3.5) + DMARC(4.5) + SaaS(10) - catchall_empty(20) = 28
			expectedScoreMin: 20,
			expectedScoreMax: 35,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "Google Workspace catch-all with legitimate Calendar signal",
			input: models.RiskAnalysis{
				IsCatchAll:        true,
				MxProvider:        "google",
				HasSPF:            true,
				HasDMARC:          true,
				HasGoogleCalendar: true, // legitimate positive on a Google MX domain
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

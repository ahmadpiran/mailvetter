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
			name: "Standard Catch-All (No Footprint)",
			input: models.RiskAnalysis{
				IsCatchAll:    true, // Base 30
				MxProvider:    "google",
				TimingDeltaMs: 50,
			},
			expectedScoreMin: 5,
			expectedScoreMax: 20,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "Office 365 Zombie (Pure Ghost Catch-All)",
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
			name: "O365 Catch-All Upgraded to Valid by Absolute Proof",
			input: models.RiskAnalysis{
				IsCatchAll:       true, // Base: 30
				MxProvider:       "office365",
				HasTeamsPresence: true, // Absolute Proof! (+15 score)
			},
			expectedScoreMin: 90,
			expectedScoreMax: 99,
			expectedReach:    models.ReachabilitySafe,
			expectedStatus:   models.StatusValid,
		},
		{
			name: "Absolute Proof Overrides Penalties",
			input: models.RiskAnalysis{
				IsCatchAll:    true, // Base: 30
				MxProvider:    "google",
				BreachCount:   2,   // Absolute Proof! (+45 score, Status -> Valid)
				EntropyScore:  0.9, // High entropy (Penalty bypassed by proof)
				DomainAgeDays: 5,   // New domain (Penalty bypassed by proof)
			},
			expectedScoreMin: 90,
			expectedScoreMax: 99,
			expectedReach:    models.ReachabilitySafe,
			expectedStatus:   models.StatusValid,
		},
		{
			name: "Soft Proof Shields Penalties (O365 Catch-All)",
			input: models.RiskAnalysis{
				IsCatchAll:       true, // Base: 30
				MxProvider:       "office365",
				HasGitHub:        true, // Soft Proof! (+12 score)
				DomainAgeDays:    5,    // New domain (Penalty bypassed by soft proof)
				HasTeamsPresence: false,
			},
			expectedScoreMin: 60,
			expectedScoreMax: 70,
			expectedReach:    models.ReachabilityRisky,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "Catch-All with Weak Timing Only",
			input: models.RiskAnalysis{
				IsCatchAll:    true, // Base: 30
				MxProvider:    "google",
				TimingDeltaMs: 2000,
			},
			expectedScoreMin: 30,
			expectedScoreMax: 40,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "High Entropy Bot (No Proof)",
			input: models.RiskAnalysis{
				SmtpStatus:   250,  // Base: 90
				EntropyScore: 0.85, // -20 penalty applies because NO proof exists
			},
			expectedScoreMin: 65,
			expectedScoreMax: 75,
			expectedReach:    models.ReachabilityRisky,
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
			name: "Unknown Domain Upgraded to Valid by Absolute Proof (Calendar)",
			input: models.RiskAnalysis{
				SmtpStatus:        0, // Base: 20
				IsCatchAll:        false,
				HasGoogleCalendar: true, // Absolute Proof! (+42.5)
			},
			// Base(20) + Calendar(42.5) + Strong Unknown Boost(50) = 112.5 (clamped to 99)
			expectedScoreMin: 90,
			expectedScoreMax: 99,
			expectedReach:    models.ReachabilitySafe,
			expectedStatus:   models.StatusValid,
		},
		{
			name: "Unknown Domain with Soft Proof (GitHub + Adobe)",
			input: models.RiskAnalysis{
				SmtpStatus: 0, // Base: 20
				IsCatchAll: false,
				HasGitHub:  true, // Soft Proof! (+12)
				HasAdobe:   true, // Soft Proof! (+18.5)
			},
			// Base(20) + GitHub(12) + Adobe(18.5) + Medium Unknown Boost(25) = 75.5 (rounds to 76)
			expectedScoreMin: 70,
			expectedScoreMax: 80,
			expectedReach:    models.ReachabilityRisky,
			expectedStatus:   models.StatusUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, _, reach, status := CalculateRobustScore(tt.input)

			if score < tt.expectedScoreMin || score > tt.expectedScoreMax {
				t.Errorf("Score %d not in range [%d, %d]", score, tt.expectedScoreMin, tt.expectedScoreMax)
			}

			if reach != tt.expectedReach {
				t.Errorf("Reachability %s != expected %s", reach, tt.expectedReach)
			}

			if tt.expectedStatus != "" && status != tt.expectedStatus {
				t.Errorf("Status %s != expected %s", status, tt.expectedStatus)
			}
		})
	}
}

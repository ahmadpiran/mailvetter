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
				// Empty CatchAll Penalty: -20
				// Result: 10
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
			// Base (30) - Zombie Penalty (30) = 0
			expectedScoreMin: 0,
			expectedScoreMax: 10,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
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
			// Base(30) + Breach(45) + Strong CatchAll(50) = 125 (clamped to 99)
			// Status should be Valid, not CatchAll, and penalties should be completely ignored.
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
				HasGitHub:        true,  // Soft Proof! (+12 score)
				DomainAgeDays:    5,     // New domain (Penalty bypassed by soft proof)
				HasTeamsPresence: false, // Would normally trigger -30 O365 Zombie penalty
			},
			// Base(30) + GitHub(12) = 42
			// Both the New Domain penalty (-50) and O365 Zombie penalty (-30) are safely bypassed!
			expectedScoreMin: 40,
			expectedScoreMax: 50,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "Catch-All with Weak Timing Only",
			input: models.RiskAnalysis{
				IsCatchAll:    true, // Base: 30
				MxProvider:    "google",
				TimingDeltaMs: 2000, // Weak Timing (+25 score) - INTENTIONALLY NOT A SOFT PROOF SHIELD
			},
			// Base(30) + Weak Timing(25) - Empty CatchAll Penalty(-20) = 35
			// Claude's logic deliberately exposes weak timing to the empty catch-all penalty
			// to balance out noisy SOCKS5 proxy jitter.
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
			// Expect an absolute 0 and Invalid status
			expectedScoreMin: 0,
			expectedScoreMax: 0,
			expectedStatus:   models.StatusInvalid,
			expectedReach:    models.ReachabilityBad,
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

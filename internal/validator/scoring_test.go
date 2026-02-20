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
				IsCatchAll:    true, // 30
				MxProvider:    "google",
				TimingDeltaMs: 50,
				// Penalty: -20
				// Result: 10
			},
			expectedScoreMin: 5,
			expectedScoreMax: 20,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "Office 365 Zombie (Catch-All Domain)",
			input: models.RiskAnalysis{
				// THE FIX: We explicitly test the Zombie penalty on Catch-Alls now
				IsCatchAll:       true,
				MxProvider:       "office365",
				HasTeamsPresence: true,
				HasSharePoint:    false,
				HasSaaSTokens:    true,
			},
			// Base (30) + Teams (15) + SaaS (10) - O365 Unlicensed Penalty (20) = 35
			expectedScoreMin: 30,
			expectedScoreMax: 50,
			expectedReach:    models.ReachabilityBad,
			expectedStatus:   models.StatusCatchAll,
		},
		{
			name: "Office 365 Valid Employee",
			input: models.RiskAnalysis{
				SmtpStatus:       250,
				MxProvider:       "office365",
				HasTeamsPresence: true,
				HasSharePoint:    true,
			},
			expectedScoreMin: 95,
			expectedScoreMax: 99,
			expectedReach:    models.ReachabilitySafe,
			expectedStatus:   models.StatusValid,
		},
		{
			name: "High Entropy Bot",
			input: models.RiskAnalysis{
				SmtpStatus:   250,
				EntropyScore: 0.85,
			},
			expectedScoreMin: 65,
			expectedScoreMax: 75,
			expectedReach:    models.ReachabilityRisky,
		},
		{
			name: "Historical Proof (HIBP Boost)",
			input: models.RiskAnalysis{
				IsCatchAll:  true, // 30
				BreachCount: 2,    // +45 = 75
				// Strong Proof Boost (New): +50
				// Result: > 100 -> 99
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
				IsPostmasterBroken: true, // THE FIX: This no longer rescues the email
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

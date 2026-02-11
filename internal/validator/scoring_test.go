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
			name: "Office 365 Zombie (The 'Riya' Case)",
			input: models.RiskAnalysis{
				SmtpStatus:       250,
				MxProvider:       "office365",
				HasTeamsPresence: true,
				HasSharePoint:    false,
				HasSaaSTokens:    true,
			},
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
			name: "Broken Server (Postmaster Fail)",
			input: models.RiskAnalysis{
				SmtpStatus:         550,
				IsPostmasterBroken: true,
			},
			expectedScoreMin: 35,
			expectedScoreMax: 45,
			expectedStatus:   models.StatusUnknown,
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

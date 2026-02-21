package validator

import (
	"mailvetter/internal/models"
	"math"
)

// Weights
const (
	WeightTeams      = 15.0
	WeightSharePoint = 60.0
	WeightCalendar   = 42.5

	WeightProofpoint = 15.0
	WeightSalesforce = 10.0

	WeightGitHub   = 12.0
	WeightGravatar = 10.0
	WeightAdobe    = 18.5
	WeightBreach   = 45.0

	WeightVRFY = 99.0

	WeightSPF   = 3.5
	WeightDMARC = 4.5
)

func CalculateRobustScore(analysis models.RiskAnalysis) (int, map[string]float64, models.Reachability, models.VerificationStatus) {
	score := 0.0
	breakdown := make(map[string]float64)
	var reachability models.Reachability
	var status models.VerificationStatus

	// 1. BASE SCORING
	if analysis.SmtpStatus == 250 {
		score = 90.0
		breakdown["base_smtp_valid"] = 90.0
		status = models.StatusValid
	} else if analysis.SmtpStatus == 550 {
		return 0, map[string]float64{"base_hard_bounce": 0}, models.ReachabilityBad, models.StatusInvalid
	} else if analysis.IsCatchAll {
		score = 30.0
		breakdown["base_catch_all"] = 30.0
		status = models.StatusCatchAll
	} else {
		score = 20.0
		breakdown["base_unknown"] = 20.0
		status = models.StatusUnknown
	}

	// Define Proof Tiers early so they can shield against penalties.
	//
	// hasAbsoluteProof: signals that unambiguously confirm a real human inbox.
	// Shields all heuristic penalties and the O365 zombie penalty.
	// TimingDeltaMs > 3000 qualifies here because it represents a very
	// deliberate, multi-second server-side delay — a strong tarpitting signal.
	hasAbsoluteProof := analysis.HasVRFY ||
		analysis.BreachCount > 0 ||
		analysis.HasGoogleCalendar ||
		analysis.TimingDeltaMs > 3000 ||
		analysis.HasTeamsPresence ||
		analysis.HasSharePoint

	// hasSoftProof: secondary identity signals from third-party platforms.
	// Also shields heuristic penalties and the O365 zombie penalty, but does
	// NOT include timing delta. Timing is already rewarded with +25 pts in the
	// boosters block; granting it penalty-immunity on top would be too generous
	// given that a single noisy probe pair can produce a delta > 1500ms.
	hasSoftProof := analysis.HasGitHub || analysis.HasAdobe || analysis.HasGravatar

	// 2. BOOSTERS
	if analysis.HasVRFY {
		return 99, map[string]float64{"p0_vrfy_verified": 99.0}, models.ReachabilitySafe, models.StatusValid
	}

	if analysis.HasTeamsPresence {
		score += WeightTeams
		breakdown["p0_teams_identity"] = WeightTeams
	}
	if analysis.HasSharePoint {
		score += WeightSharePoint
		breakdown["p0_sharepoint_license"] = WeightSharePoint
	}

	if analysis.HasGoogleCalendar {
		score += WeightCalendar
		breakdown["p0_calendar"] = WeightCalendar
	}
	if analysis.HasAdobe {
		score += WeightAdobe
		breakdown["p2_adobe"] = WeightAdobe
	}

	if analysis.HasGitHub {
		score += WeightGitHub
		breakdown["p2_github"] = WeightGitHub
	}
	if analysis.HasGravatar {
		score += WeightGravatar
		breakdown["p2_gravatar"] = WeightGravatar
	}

	if analysis.BreachCount > 0 {
		boost := WeightBreach
		if analysis.BreachCount > 5 {
			boost += 10.0
		}
		score += boost
		breakdown["p1_historical_breach"] = boost
		if status == models.StatusCatchAll {
			status = models.StatusValid
		}
	}

	if analysis.MxProvider == "proofpoint" || analysis.MxProvider == "mimecast" {
		score += WeightProofpoint
		breakdown["p1_enterprise_sec"] = WeightProofpoint
	}
	if analysis.HasSaaSTokens {
		score += WeightSalesforce
		breakdown["p1_saas_usage"] = WeightSalesforce
	}
	if analysis.HasSPF {
		score += WeightSPF
		breakdown["p2_spf"] = WeightSPF
	}
	if analysis.HasDMARC {
		score += WeightDMARC
		breakdown["p2_dmarc"] = WeightDMARC
	}

	if analysis.TimingDeltaMs > 3000 {
		score += 50.0
		breakdown["p2_timing_strong"] = 50.0
	} else if analysis.TimingDeltaMs > 1500 {
		score += 25.0
		breakdown["p2_timing_weak"] = 25.0
	}

	// 3. PENALTIES
	// Both Absolute and Soft proofs shield against harsh heuristics.
	// A confirmed identity (breach record, GitHub, Adobe, etc.) makes
	// entropy and domain-age penalties irrelevant.
	if !hasAbsoluteProof && !hasSoftProof {
		if analysis.EntropyScore > 0.5 {
			score -= 20.0
			breakdown["penalty_high_entropy"] = -20.0
		}
		if analysis.IsRoleAccount {
			score -= 10.0
			breakdown["penalty_role_account"] = -10.0
		}
		if analysis.DomainAgeDays > 0 && analysis.DomainAgeDays < 30 {
			score -= 50.0
			breakdown["penalty_new_domain"] = -50.0
		}
	}

	// 4. O365 ZOMBIE PENALTY
	// Applied only when the domain is a catch-all with no identity proof.
	// Soft proofs (e.g. GitHub) are sufficient to bypass this because they
	// confirm the person exists independently of the O365 license check.
	// The status guard ensures a breach-promoted StatusValid is never
	// overwritten back to StatusCatchAll by this block.
	if analysis.MxProvider == "office365" && analysis.IsCatchAll && !hasAbsoluteProof && !hasSoftProof {
		if !analysis.HasTeamsPresence && !analysis.HasSharePoint {
			score -= 30.0
			breakdown["penalty_o365_ghost"] = -30.0
			if status != models.StatusValid {
				status = models.StatusCatchAll
			}
		}
	}

	// 5. CATCH-ALL DISAMBIGUATION
	// FIX: Removed the Office365 exclusion. If an O365 email is hiding behind
	// an Accept-All firewall, but we find Absolute Proof (like Teams presence),
	// it MUST be upgraded to Valid.
	if analysis.IsCatchAll {
		if hasAbsoluteProof {
			boost := 50.0
			score += boost
			breakdown["resolution_catchall_strong"] = boost
			status = models.StatusValid // Upgrades Catch-All to Valid!
		} else if hasSoftProof {
			boost := 25.0
			score += boost
			breakdown["resolution_catchall_medium"] = boost
		} else {
			// Apply the empty penalty only if it's NOT O365,
			// because O365 already received the specific -30 Zombie penalty in Step 4.
			if analysis.MxProvider != "office365" {
				penalty := -20.0
				score += penalty
				breakdown["resolution_catchall_empty"] = penalty
			}
		}
	}

	// 6. FINALIZE
	finalScore := int(math.Round(score))
	if finalScore > 99 {
		finalScore = 99
	}
	if finalScore < 0 {
		finalScore = 0
	}

	if finalScore >= 90 {
		reachability = models.ReachabilitySafe
	} else if finalScore >= 60 {
		reachability = models.ReachabilityRisky
	} else {
		reachability = models.ReachabilityBad
	}

	return finalScore, breakdown, reachability, status
}

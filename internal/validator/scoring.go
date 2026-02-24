package validator

import (
	"mailvetter/internal/models"
	"math"
)

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

	// ── 1. Base score ────────────────────────────────────────────────────────
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

	// ── 2. VRFY golden ticket — short-circuit immediately ───────────────────
	if analysis.HasVRFY {
		return 99, map[string]float64{"p0_vrfy_verified": 99.0}, models.ReachabilitySafe, models.StatusValid
	}

	// ── 3. O365 zombie correction ────────────────────────────────────────────
	//
	// Office 365 is notorious for returning SMTP 250 OK for users who exist in
	// Azure AD but either have no Exchange license or have been blocked from
	// receiving mail. A raw score of 90 for such an address is a false positive
	// that would cause real mail to be sent to an undeliverable inbox.
	//
	// We correct this before adding any proof boosts so the final score
	// accurately reflects deliverability rather than mere identity existence.
	if analysis.MxProvider == "office365" && analysis.SmtpStatus == 250 && !analysis.HasSharePoint {
		if analysis.HasTeamsPresence {
			// Identity confirmed in Azure AD / Teams, but no SharePoint/Exchange
			// license means the mailbox cannot receive mail. This is the classic
			// "zombie" account — the user exists but is undeliverable.
			//
			// correction_o365_false_positive revokes the 90-point base score.
			// penalty_o365_unlicensed adds a further deduction to reflect that
			// we have positive proof the mailbox is inactive.
			score += -60.0
			breakdown["correction_o365_false_positive"] = -60.0
			score += -20.0
			breakdown["penalty_o365_unlicensed"] = -20.0
			status = models.StatusCatchAll
		} else {
			// SMTP said 250 but the user has zero Microsoft footprint — no Teams
			// presence, no SharePoint. O365 is lying outright (ghost account).
			// Apply the false-positive correction and the ghost penalty.
			score += -60.0
			breakdown["correction_o365_false_positive"] = -60.0
			score += -30.0
			breakdown["penalty_o365_ghost"] = -30.0
			status = models.StatusCatchAll
		}
	}

	// ── 4. Proof signals ─────────────────────────────────────────────────────
	hasAbsoluteProof := analysis.HasVRFY ||
		analysis.BreachCount > 0 ||
		analysis.HasGoogleCalendar ||
		analysis.TimingDeltaMs > 3000 ||
		analysis.HasTeamsPresence ||
		analysis.HasSharePoint

	hasSoftProof := analysis.HasGitHub || analysis.HasAdobe || analysis.HasGravatar

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

	// ── 5. Penalties (only when no proof exists to shield them) ──────────────
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

	// ── 6. Catch-all resolution ───────────────────────────────────────────────
	// For non-O365 catch-alls (O365 catch-alls without SMTP 250 are handled
	// by the existing ghost penalty path preserved below).
	if analysis.IsCatchAll {
		if hasAbsoluteProof {
			score += 50.0
			breakdown["resolution_catchall_strong"] = 50.0
			status = models.StatusValid
		} else if hasSoftProof {
			score += 25.0
			breakdown["resolution_catchall_medium"] = 25.0
		} else {
			if analysis.MxProvider != "office365" {
				score += -20.0
				breakdown["resolution_catchall_empty"] = -20.0
			}
		}
	}

	// ── 7. Unknown domain resolution ─────────────────────────────────────────
	if status == models.StatusUnknown {
		if hasAbsoluteProof {
			score += 50.0
			breakdown["resolution_unknown_strong"] = 50.0
			status = models.StatusValid
		} else if hasSoftProof {
			score += 25.0
			breakdown["resolution_unknown_medium"] = 25.0
		}
	}

	// ── 8. Clamp, band, return ────────────────────────────────────────────────
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

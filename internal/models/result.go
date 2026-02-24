package models

type VerificationStatus string
type Reachability string

const (
	StatusValid    VerificationStatus = "valid"
	StatusInvalid  VerificationStatus = "invalid"
	StatusRisky    VerificationStatus = "risky"
	StatusCatchAll VerificationStatus = "catch_all"
	StatusUnknown  VerificationStatus = "unknown"

	ReachabilitySafe    Reachability = "safe"
	ReachabilityRisky   Reachability = "risky"
	ReachabilityBad     Reachability = "bad"
	ReachabilityUnknown Reachability = "unknown"
)

type RiskAnalysis struct {
	// P0: Critical
	SmtpStatus        int  `json:"smtp_status"`
	HasTeamsPresence  bool `json:"has_teams_presence"`
	HasGoogleCalendar bool `json:"has_google_calendar"`
	HasSharePoint     bool `json:"has_sharepoint"`

	// Golden Tickets
	HasVRFY bool `json:"has_vrfy"`

	// P1: High Value
	IsCatchAll    bool   `json:"is_catch_all"`
	MxProvider    string `json:"mx_provider"`
	HasSaaSTokens bool   `json:"has_saas_tokens"`

	// Extended Socials
	HasAdobe bool `json:"has_adobe"`

	// Social & History
	HasGitHub   bool `json:"has_github"`
	HasGravatar bool `json:"has_gravatar"`
	BreachCount int  `json:"breach_count"`

	// Syntax / Hygiene
	IsRoleAccount      bool    `json:"is_role_account"`
	EntropyScore       float64 `json:"entropy_score"`
	IsPostmasterBroken bool    `json:"is_postmaster_broken"`

	// P2: Medium
	TimingDeltaMs int64 `json:"timing_delta_ms"`
	HasDMARC      bool  `json:"has_dmarc"`
	HasSPF        bool  `json:"has_spf"`
	IsGreylisted  bool  `json:"is_greylisted"`

	// P3: Low
	DomainAgeDays int  `json:"domain_age_days"`
	HasTLS13      bool `json:"has_tls13"`
}

type ValidationResult struct {
	Email          string             `json:"email"`
	Score          int                `json:"score"`
	ScoreBreakdown map[string]float64 `json:"score_details"`
	Status         VerificationStatus `json:"status"`
	Reachability   Reachability       `json:"reachability"`
	Analysis       RiskAnalysis       `json:"analysis"`
	Duration       string             `json:"duration"`
	Error          string             `json:"error,omitempty"`
}

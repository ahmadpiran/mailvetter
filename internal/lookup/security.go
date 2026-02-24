package lookup

import (
	"context"
	"net"
	"strings"
)

// CheckSPF looks for a valid SPF record in TXT entries.
func CheckSPF(ctx context.Context, domain string) bool {
	txts, err := net.DefaultResolver.LookupTXT(ctx, domain)
	if err != nil {
		return false
	}
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=spf1") {
			return true
		}
	}
	return false
}

// CheckDMARC looks for a DMARC policy record.
// Presence of DMARC implies active IT management of the domain.
func CheckDMARC(ctx context.Context, domain string) bool {
	txts, err := net.DefaultResolver.LookupTXT(ctx, "_dmarc."+domain)
	if err != nil {
		return false
	}
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=DMARC1") {
			return true
		}
	}
	return false
}

// CheckSaaSTokens scans DNS TXT records for proof of B2B SaaS tool usage.
// Finding tokens for tools like Salesforce or Zendesk proves the domain is
// actively used for business operations, not just registered and parked.
func CheckSaaSTokens(ctx context.Context, domain string) bool {
	txts, err := net.DefaultResolver.LookupTXT(ctx, domain)
	if err != nil {
		return false
	}

	indicators := []string{
		"salesforce",
		"zendesk",
		"atlassian",
		"docusign",
		"facebook-domain-verification",
		"apple-domain-verification",
		"stripe",
	}

	for _, txt := range txts {
		lowerTxt := strings.ToLower(txt)
		for _, ind := range indicators {
			if strings.Contains(lowerTxt, ind) {
				return true
			}
		}
	}
	return false
}

// IdentifyProvider analyses MX records to categorise the email infrastructure.
// Returns a canonical provider string used by the scoring engine to apply
// appropriate boosts and corrections.
//
// Recognised providers and their canonical names:
//
//	Enterprise security gateways (trigger p1_enterprise_sec boost):
//	  "proofpoint" — Proofpoint (pphosted.com)
//	  "mimecast"   — Mimecast (mimecast.com)
//	  "barracuda"  — Barracuda Networks (barracudanetworks.com)
//	  "ironport"   — Cisco IronPort / Cisco Secure Email (iphmx.com)
//
//	Major hosted providers:
//	  "google"    — Google Workspace (google.com, googlemail.com)
//	  "office365" — Microsoft 365 (outlook.com, protection.outlook.com)
//
//	Fallback:
//	  "generic"   — anything not matched above
//
// CHANGE: Added "ironport" for iphmx.com (Cisco IronPort / Cisco Secure Email
// Gateway). IronPort was already present in smtp.go's strictGateways list —
// the SMTP layer correctly identified it as an enterprise gateway requiring
// extended timeouts and careful handling — but it was absent from this function,
// causing it to fall through to "generic". That meant the scoring engine never
// awarded the p1_enterprise_sec boost and never exempted it from the
// resolution_catchall_empty penalty, producing scores that were too low for
// domains that have invested in Cisco's enterprise email security stack.
func IdentifyProvider(ctx context.Context, domain string) (string, error) {
	mxRecords, err := CheckDNS(ctx, domain)
	if err != nil {
		return "generic", err
	}

	for _, mx := range mxRecords {
		host := strings.ToLower(mx.Host)

		// ── Enterprise security gateways ─────────────────────────────────────
		// Checked first because some organisations route through a gateway
		// in front of Google or Microsoft, and the gateway is the more
		// meaningful signal for scoring purposes.
		if strings.Contains(host, "pphosted.com") {
			return "proofpoint", nil
		}
		if strings.Contains(host, "mimecast.com") {
			return "mimecast", nil
		}
		if strings.Contains(host, "barracudanetworks.com") {
			return "barracuda", nil
		}
		// iphmx.com is the MX hostname pattern for Cisco IronPort /
		// Cisco Secure Email Gateway (formerly IronPort Systems, acquired
		// by Cisco in 2007). It is a paid enterprise product deployed
		// exclusively by mid-to-large organisations — the same signal
		// strength as Proofpoint or Mimecast.
		if strings.Contains(host, "iphmx.com") {
			return "ironport", nil
		}

		// ── Major hosted providers ────────────────────────────────────────────
		if strings.Contains(host, "google.com") || strings.Contains(host, "googlemail.com") {
			return "google", nil
		}
		if strings.Contains(host, "outlook.com") || strings.Contains(host, "protection.outlook.com") {
			return "office365", nil
		}
	}

	return "generic", nil
}

package lookup

import (
	"context"
	"net"
	"strings"
)

// CheckSPF looks for a valid SPF record in TXT entries.
func CheckSPF(ctx context.Context, domain string) bool {
	// Use the context-aware resolver. The previous call to net.LookupTXT
	// accepted ctx but never passed it anywhere, meaning a cancelled or timed-out
	// context had no effect on these DNS calls.
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
	// DMARC is always published at _dmarc.<domain>
	txts, err := net.DefaultResolver.LookupTXT(ctx, "_dmarc."+domain) // FIX 1
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
	txts, err := net.DefaultResolver.LookupTXT(ctx, domain) // FIX 1
	if err != nil {
		return false
	}

	// Removed "google-site-verification" from this list.
	// Almost every Google Workspace domain has this TXT record — it's an
	// infrastructure ownership signal, not evidence of B2B SaaS usage.
	// Including it caused the p1_saas_usage score boost to fire for the
	// vast majority of Google-hosted domains regardless of actual tool adoption.
	// Provider identification is already handled by IdentifyProvider.
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

// IdentifyProvider analyzes MX records to categorize the email infrastructure.
// Returns a canonical provider string: "proofpoint", "mimecast", "barracuda",
// "google", "office365", or "generic". Never returns "unknown" — callers should
// not need to normalise the return value.
func IdentifyProvider(ctx context.Context, domain string) (string, error) {
	mxRecords, err := CheckDNS(ctx, domain)
	if err != nil {
		return "generic", err // FIX 3: Return "generic" on error, not "unknown".
	}

	for _, mx := range mxRecords {
		host := strings.ToLower(mx.Host)

		// 1. Enterprise Security Gateways (High Value)
		if strings.Contains(host, "pphosted.com") {
			return "proofpoint", nil
		}
		if strings.Contains(host, "mimecast.com") {
			return "mimecast", nil
		}
		if strings.Contains(host, "barracudanetworks.com") {
			return "barracuda", nil
		}

		// 2. Major Hosted Providers (High Reliability)
		if strings.Contains(host, "google.com") || strings.Contains(host, "googlemail.com") {
			return "google", nil
		}
		if strings.Contains(host, "outlook.com") || strings.Contains(host, "protection.outlook.com") {
			return "office365", nil
		}
	}

	return "generic", nil
}

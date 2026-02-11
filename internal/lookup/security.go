package lookup

import (
	"context"
	"net"
	"strings"
)

// CheckSPF looks for a valid SPF record in TXT entries.
func CheckSPF(ctx context.Context, domain string) bool {
	txts, err := net.LookupTXT(domain)
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
// Presence of DMARC implies active IT management.
func CheckDMARC(ctx context.Context, domain string) bool {
	// DMARC is always at _dmarc.domain.com
	dmarcDomain := "_dmarc." + domain
	txts, err := net.LookupTXT(dmarcDomain)
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

// CheckSaaSTokens scans DNS TXT records for proof of B2B tool usage.
// Finding Salesforce or Zendesk tokens proves the domain is used for business.
func CheckSaaSTokens(ctx context.Context, domain string) bool {
	txts, err := net.LookupTXT(domain)
	if err != nil {
		return false
	}

	// Tokens to look for
	indicators := []string{
		"google-site-verification",
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
func IdentifyProvider(ctx context.Context, domain string) (string, error) {
	mxRecords, err := CheckDNS(ctx, domain)
	if err != nil {
		return "unknown", err
	}

	for _, mx := range mxRecords {
		host := strings.ToLower(mx.Host)

		// 1. Enterprise Security (High Value)
		if strings.Contains(host, "pphosted.com") {
			return "proofpoint", nil
		}
		if strings.Contains(host, "mimecast.com") {
			return "mimecast", nil
		}
		if strings.Contains(host, "barracudanetworks.com") {
			return "barracuda", nil
		}

		// 2. Big Tech (High Reliability)
		if strings.Contains(host, "google.com") || strings.Contains(host, "googlemail.com") {
			return "google", nil
		}
		if strings.Contains(host, "outlook.com") || strings.Contains(host, "protection.outlook.com") {
			return "office365", nil
		}
	}

	return "generic", nil
}

package lookup

import (
	"strings"
	"unicode"
)

// Common disposable domains
var disposableDomains = map[string]struct{}{
	"temp-mail.org": {}, "10minutemail.com": {}, "guerrillamail.com": {},
	"mailinator.com": {}, "yopmail.com": {}, "throwawaymail.com": {},
	"tempmail.net": {}, "sharklasers.com": {}, "dispostable.com": {},
}

// MX servers that indicate the domain is inactive/parked
var parkedMXHosts = []string{
	"secureserver.net",  // GoDaddy Parking
	"parking.reg.ru",    // Registrar Parking
	"namecheap.com",     // Namecheap Parking
	"domaincontrol.com", // GoDaddy
}

// Common role-based prefixes (Upgraded to Map for performance)
var roleAccounts = map[string]bool{
	"admin": true, "support": true, "info": true, "sales": true,
	"contact": true, "help": true, "office": true, "marketing": true,
	"jobs": true, "billing": true, "abuse": true, "postmaster": true,
	"noreply": true, "no-reply": true, "webmaster": true, "hostmaster": true,
	"hr": true,
}

// IsDisposableDomain checks if the domain is a known burner provider.
func IsDisposableDomain(domain string) bool {
	_, exists := disposableDomains[strings.ToLower(domain)]
	return exists
}

// IsRoleAccount checks if the user part is a generic function/role.
func IsRoleAccount(email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	user := strings.ToLower(parts[0])
	return roleAccounts[user]
}

// IsParkedDomain checks if the MX record points to a known parking service.
func IsParkedDomain(mxHost string) bool {
	host := strings.ToLower(mxHost)
	for _, parked := range parkedMXHosts {
		if strings.Contains(host, parked) {
			return true
		}
	}
	return false
}

// CalculateEntropy measures the "randomness" of a string.
// High entropy (e.g. "x9f2k1") indicates a bot/burner.
// Returns the ratio of digits to total length.
func CalculateEntropy(s string) float64 {
	if s == "" {
		return 0
	}

	digits := 0.0
	length := float64(len(s))

	for _, char := range s {
		if unicode.IsDigit(char) {
			digits++
		}
	}

	// Returns the percentage of digits.
	// > 0.5 (50% numbers) is suspicious.
	return digits / length
}

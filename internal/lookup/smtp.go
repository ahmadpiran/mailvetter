package lookup

import (
	"context"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"
)

const (
	HeloHost = "mta1.mailvetter.com" // Identify yourself politely
	MailFrom = "verify@mailvetter.com"
)

// CheckSMTP performs a standard probe via direct connection.
func CheckSMTP(ctx context.Context, mxHost string, targetEmail string) (bool, time.Duration, error) {
	start := time.Now()

	// 1. Direct connection (Bypass proxy for Port 25)
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", mxHost+":25")
	if err != nil {
		return false, 0, fmt.Errorf("connection failed: %w", err)
	}

	// 2. Anti-tarpit deadline
	conn.SetDeadline(time.Now().Add(12 * time.Second))

	client, err := smtp.NewClient(conn, mxHost)
	if err != nil {
		conn.Close()
		return false, 0, fmt.Errorf("client handshake failed: %w", err)
	}
	defer client.Close()

	if err = client.Hello(HeloHost); err != nil {
		return false, time.Since(start), fmt.Errorf("HELO failed: %w", err)
	}

	if err = client.Mail(MailFrom); err != nil {
		return false, time.Since(start), fmt.Errorf("MAIL FROM failed: %w", err)
	}

	err = client.Rcpt(targetEmail)
	elapsed := time.Since(start)

	if err != nil {
		return false, elapsed, err
	}

	_ = client.Quit()
	return true, elapsed, nil
}

// CheckPostmaster verifies if the domain accepts emails to postmaster
func CheckPostmaster(ctx context.Context, mxHost, domain string) bool {
	// A standard compliant mail server MUST accept mail to postmaster.
	success, _, err := CheckSMTP(ctx, mxHost, "postmaster@"+domain)
	if success {
		return true
	}
	if IsNoSuchUserError(err) {
		return false
	}
	// If rate-limited or timed out, assume true to avoid penalizing the user's score unfairly
	return true
}

// CheckVRFY attempts to verify the user using the VRFY command.
func CheckVRFY(ctx context.Context, mxHost string, targetEmail string) bool {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", mxHost+":25")
	if err != nil {
		return false
	}
	defer conn.Close()

	// Anti-tarpit deadline
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	tp := textproto.NewConn(conn)
	defer tp.Close()

	_, _, err = tp.ReadResponse(220)
	if err != nil {
		return false
	}

	if _, err = tp.Cmd("HELO %s", HeloHost); err != nil {
		return false
	}
	_, _, err = tp.ReadResponse(250)
	if err != nil {
		return false
	}

	id, err := tp.Cmd("VRFY %s", targetEmail)
	if err != nil {
		return false
	}

	_, _, err = tp.ReadResponse(250)
	return err == nil && (id == 250 || id == 251)
}

// --- Helper Functions ---

// IsNoSuchUserError determines if the SMTP error means the mailbox does not exist
func IsNoSuchUserError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())

	// Standard SMTP error codes for "user unknown"
	if strings.Contains(errStr, "550") || strings.Contains(errStr, "5.1.1") {
		return true
	}

	// Provider-specific string matching for common rejections
	keywords := []string{
		"does not exist", "user unknown", "no such user",
		"recipient rejected", "not found", "invalid mailbox",
		"not a valid mailbox",
	}

	for _, kw := range keywords {
		if strings.Contains(errStr, kw) {
			return true
		}
	}
	return false
}

// IsRateLimitError checks if the server is asking us to slow down
func IsRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "450") ||
		strings.Contains(errStr, "451") ||
		strings.Contains(errStr, "452") ||
		strings.Contains(errStr, "too many requests") ||
		strings.Contains(errStr, "rate limit")
}

// IsCatchAll tests a fake email address to see if the server accepts everything
func IsCatchAll(ctx context.Context, mxHost, domain string) bool {
	fakeEmail := fmt.Sprintf("bounce-test-%d@%s", time.Now().UnixNano(), domain)
	success, _, _ := CheckSMTP(ctx, mxHost, fakeEmail)
	return success
}

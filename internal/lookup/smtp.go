package lookup

import (
	"context"
	"errors"
	"fmt"
	"mailvetter/internal/proxy"
	"net"
	"net/textproto"
	"strings"
	"time"
)

const (
	HeloHost = "mta1.mailvetter.com" // Identify yourself politely
	MailFrom = ""
)

// Prevents the VPS IP from being banned by Google/Outlook for opening too many concurrent connections.
var SMTPSemaphore = make(chan struct{}, 15)

// CheckSMTP performs a standard probe via direct or proxy connection,
// with adaptive protocol speeds to bypass enterprise tarpits.
func CheckSMTP(ctx context.Context, mxHost string, targetEmail string) (bool, time.Duration, error) {
	// Semaphore acquisition is now context-aware.
	select {
	case SMTPSemaphore <- struct{}{}:
	case <-ctx.Done():
		return false, 0, ctx.Err()
	}
	defer func() { <-SMTPSemaphore }()

	var conn net.Conn
	var err error

	if proxy.SMTPEnabled {
		conn, err = proxy.DialContext(ctx, "tcp", mxHost+":25", 10*time.Second)
	} else {
		d := net.Dialer{Timeout: 10 * time.Second}
		conn, err = d.DialContext(ctx, "tcp4", mxHost+":25")
	}

	if err != nil {
		return false, 0, fmt.Errorf("connection failed: %w", err)
	}

	start := time.Now()

	// 1. Detect Strict Enterprise Gateways (SEGs)
	mxLower := strings.ToLower(mxHost)
	isStrictEnterprise := false

	strictGateways := []string{
		"mimecast.com",          // Mimecast
		"pphosted.com",          // Proofpoint
		"barracudanetworks.com", // Barracuda
		"messagelabs.com",       // Symantec / Broadcom MessageLabs
		"iphmx.com",             // Cisco IronPort
		"trendmicro.com",        // Trend Micro
		"trendmicro.eu",         // Trend Micro (EU)
		"sophos.com",            // Sophos
		"mailcontrol.com",       // Forcepoint / Websense
		"mxlogic.net",           // McAfee / Trellix
		"fireeye.com",           // FireEye
		"mx.cloudflare.net",     // Cloudflare Area 1
	}

	for _, gw := range strictGateways {
		if strings.Contains(mxLower, gw) {
			isStrictEnterprise = true
			break
		}
	}

	// 2. Adjust connection deadline
	// If we are artificially delaying commands, we need to give the connection
	// more time to live so we don't accidentally time ourselves out.
	deadlineOffset := 12 * time.Second
	if isStrictEnterprise {
		deadlineOffset = 16 * time.Second
	}

	deadline := time.Now().Add(deadlineOffset)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	conn.SetDeadline(deadline)

	// NEW: Use textproto directly instead of smtp.NewClient!
	tp := textproto.NewConn(conn)
	defer tp.Close()

	smartDelay := func() error {
		if !isStrictEnterprise {
			return nil
		}
		select {
		case <-time.After(1 * time.Second):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// 1. Read 220 Welcome Banner
	if _, _, err := tp.ReadResponse(220); err != nil {
		return false, time.Since(start), fmt.Errorf("banner timeout/rejected: %w", err)
	}

	// 2. Send HELO directly (bypassing EHLO localhost)
	if err := smartDelay(); err != nil {
		return false, time.Since(start), err
	}
	if _, err := tp.Cmd("HELO %s", HeloHost); err != nil {
		return false, time.Since(start), err
	}
	if _, _, err := tp.ReadResponse(250); err != nil {
		return false, time.Since(start), fmt.Errorf("HELO rejected: %w", err)
	}

	// 3. Send MAIL FROM
	if err := smartDelay(); err != nil {
		return false, time.Since(start), err
	}
	if _, err := tp.Cmd("MAIL FROM:<%s>", MailFrom); err != nil {
		return false, time.Since(start), err
	}
	if _, _, err := tp.ReadResponse(250); err != nil {
		return false, time.Since(start), fmt.Errorf("MAIL FROM rejected: %w", err)
	}

	// 4. Send RCPT TO
	if err := smartDelay(); err != nil {
		return false, time.Since(start), err
	}
	if _, err := tp.Cmd("RCPT TO:<%s>", targetEmail); err != nil {
		return false, time.Since(start), err
	}

	// Read ANY response (0) instead of expecting exactly 25.
	code, msg, err := tp.ReadResponse(0)
	elapsed := time.Since(start)

	tp.Cmd("QUIT")

	if err != nil {
		return false, elapsed, fmt.Errorf("network read error: %w", err)
	}

	// Manually check for success codes (250 OK or 251 Forwarded)
	if code == 250 || code == 251 {
		return true, elapsed, nil
	}

	// If the server rejected the email (5xx or 4xx), package the error
	// so IsNoSuchUserError can read it properly!
	return false, elapsed, &textproto.Error{Code: code, Msg: msg}
}

// CheckPostmaster verifies if the domain accepts emails to postmaster.
// Returns true (postmaster working) on any non-definitive failure to avoid
// incorrectly marking a domain as broken due to transient network issues.
// Note: rate-limit and timeout errors both cause this to return true (fail open).
func CheckPostmaster(ctx context.Context, mxHost, domain string) bool {
	success, _, err := CheckSMTP(ctx, mxHost, "postmaster@"+domain)
	if success {
		return true
	}
	if IsNoSuchUserError(err) {
		return false
	}
	return true
}

// CheckVRFY attempts to verify the user using the VRFY command.
func CheckVRFY(ctx context.Context, mxHost string, targetEmail string) bool {
	// Semaphore acquisition is now context-aware, same as CheckSMTP.
	select {
	case SMTPSemaphore <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	defer func() { <-SMTPSemaphore }()

	var conn net.Conn
	var err error

	if proxy.SMTPEnabled {
		conn, err = proxy.DialContext(ctx, "tcp", mxHost+":25", 10*time.Second)
	} else {
		d := net.Dialer{Timeout: 10 * time.Second}
		conn, err = d.DialContext(ctx, "tcp", mxHost+":25")
	}

	if err != nil {
		return false
	}
	defer conn.Close()

	// Respect the context deadline instead of a fixed 10-second wall-clock offset.
	deadline := time.Now().Add(10 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	conn.SetDeadline(deadline)

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

	// tp.Cmd() returns a pipeline MsgId (a small incrementing integer),
	// NOT the SMTP response code. The previous code compared this id against 250/251,
	// which could never be true, making CheckVRFY silently always return false.
	// The response code must be read separately via tp.ReadResponse().
	if _, err = tp.Cmd("VRFY %s", targetEmail); err != nil {
		return false
	}
	code, _, err := tp.ReadResponse(250)
	return err == nil && (code == 250 || code == 251)
}

// --- Helper Functions ---

// IsNoSuchUserError determines if the SMTP error means the mailbox does not exist.
func IsNoSuchUserError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	// 1. SHIELD: Check for block/spam/policy keywords FIRST
	// If the server explicitly says "blocked", it is a network error, NOT a missing user.
	blockKeywords := []string{
		"spam", "block", "banned", "blacklisted", "ip", "policy",
		"relay", "access denied", "rejected by network", "unauthenticated",
		"sender", "reputation", "spf", "dmarc", "dkim", "quota",
		"rate limit", "temporarily", "reverse dns", "ptr", "helo",
		"spamhaus", "barracuda", "sorbs", "client host rejected",
		"not permitted", "connection refused", "timeout", "greylist",
	}
	for _, kw := range blockKeywords {
		if strings.Contains(errStr, kw) {
			return false
		}
	}

	// 2. Specific status codes explicitly indicating invalid user
	if strings.Contains(errStr, "5.1.1") || strings.Contains(errStr, "5.1.0") {
		return true
	}

	// 3. Keywords explicitly indicating missing user
	keywords := []string{
		"does not exist", "user unknown", "no such user",
		"recipient rejected", "not found", "invalid mailbox",
		"not a valid mailbox", "mailbox unavailable", "unrouteable address",
		"no mailbox here", "unknown user", "bad destination",
		"address rejected",
	}
	for _, kw := range keywords {
		if strings.Contains(errStr, kw) {
			return true
		}
	}

	// 4. Fallback: If we didn't hit a blocklist word, and we see standard 550/551
	var textErr *textproto.Error
	if errors.As(err, &textErr) {
		if textErr.Code == 550 || textErr.Code == 551 {
			return true
		}
	}

	return false
}

// IsRateLimitError checks if the server is asking us to slow down.
func IsRateLimitError(err error) bool {
	if err == nil {
		return false
	}

	// Prefer structured error code checks over string matching.
	var textErr *textproto.Error
	if errors.As(err, &textErr) {
		return textErr.Code == 450 || textErr.Code == 451 || textErr.Code == 452
	}

	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "450") ||
		strings.Contains(errStr, "451") ||
		strings.Contains(errStr, "452") ||
		strings.Contains(errStr, "too many requests") ||
		strings.Contains(errStr, "rate limit")
}

package lookup

import (
	"context"
	"errors"
	"fmt"
	"mailvetter/internal/proxy"
	"net"
	"net/textproto"
	"net/url"
	"strings"
	"time"
)

const (
	HeloHost = "mta1.mailvetter.com"
	MailFrom = ""
)

var SMTPSemaphore = make(chan struct{}, 15)

func CheckSMTP(ctx context.Context, mxHost string, targetEmail string, pURL *url.URL) (bool, time.Duration, error) {
	select {
	case SMTPSemaphore <- struct{}{}:
	case <-ctx.Done():
		return false, 0, ctx.Err()
	}
	defer func() { <-SMTPSemaphore }()

	var conn net.Conn
	var err error

	if proxy.SMTPEnabled && pURL != nil {
		conn, err = proxy.DialContext(ctx, "tcp", mxHost+":25", 10*time.Second, pURL)
	} else {
		d := net.Dialer{Timeout: 10 * time.Second}
		conn, err = d.DialContext(ctx, "tcp4", mxHost+":25")
	}

	if err != nil {
		return false, 0, fmt.Errorf("connection failed: %w", err)
	}

	start := time.Now()
	mxLower := strings.ToLower(mxHost)
	isStrictEnterprise := false

	strictGateways := []string{
		"mimecast.com", "pphosted.com", "barracudanetworks.com", "messagelabs.com",
		"iphmx.com", "trendmicro.com", "trendmicro.eu", "sophos.com",
		"mailcontrol.com", "mxlogic.net", "fireeye.com", "mx.cloudflare.net",
	}

	for _, gw := range strictGateways {
		if strings.Contains(mxLower, gw) {
			isStrictEnterprise = true
			break
		}
	}

	deadlineOffset := 12 * time.Second
	if isStrictEnterprise {
		deadlineOffset = 16 * time.Second
	}

	deadline := time.Now().Add(deadlineOffset)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	conn.SetDeadline(deadline)

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

	if _, _, err := tp.ReadResponse(220); err != nil {
		return false, time.Since(start), fmt.Errorf("banner timeout/rejected: %w", err)
	}

	if err := smartDelay(); err != nil {
		return false, time.Since(start), err
	}
	if _, err := tp.Cmd("HELO %s", HeloHost); err != nil {
		return false, time.Since(start), err
	}
	if _, _, err := tp.ReadResponse(250); err != nil {
		return false, time.Since(start), fmt.Errorf("HELO rejected: %w", err)
	}

	if err := smartDelay(); err != nil {
		return false, time.Since(start), err
	}
	if _, err := tp.Cmd("MAIL FROM:<%s>", MailFrom); err != nil {
		return false, time.Since(start), err
	}
	if _, _, err := tp.ReadResponse(250); err != nil {
		return false, time.Since(start), fmt.Errorf("MAIL FROM rejected: %w", err)
	}

	if err := smartDelay(); err != nil {
		return false, time.Since(start), err
	}
	if _, err := tp.Cmd("RCPT TO:<%s>", targetEmail); err != nil {
		return false, time.Since(start), err
	}

	code, msg, err := tp.ReadResponse(0)
	elapsed := time.Since(start)

	tp.Cmd("QUIT")

	if err != nil {
		return false, elapsed, fmt.Errorf("network read error: %w", err)
	}

	if code == 250 || code == 251 {
		return true, elapsed, nil
	}

	return false, elapsed, &textproto.Error{Code: code, Msg: msg}
}

func CheckPostmaster(ctx context.Context, mxHost, domain string, pURL *url.URL) bool {
	success, _, err := CheckSMTP(ctx, mxHost, "postmaster@"+domain, pURL)
	if success {
		return true
	}
	if IsNoSuchUserError(err) {
		return false
	}
	return true
}

func CheckVRFY(ctx context.Context, mxHost string, targetEmail string, pURL *url.URL) bool {
	select {
	case SMTPSemaphore <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	defer func() { <-SMTPSemaphore }()

	var conn net.Conn
	var err error

	if proxy.SMTPEnabled && pURL != nil {
		conn, err = proxy.DialContext(ctx, "tcp", mxHost+":25", 10*time.Second, pURL)
	} else {
		d := net.Dialer{Timeout: 10 * time.Second}
		conn, err = d.DialContext(ctx, "tcp", mxHost+":25")
	}

	if err != nil {
		return false
	}
	defer conn.Close()

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

	if _, err = tp.Cmd("VRFY %s", targetEmail); err != nil {
		return false
	}
	code, _, err := tp.ReadResponse(250)
	return err == nil && (code == 250 || code == 251)
}

func IsNoSuchUserError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())

	if strings.Contains(errStr, "5.1.1") || strings.Contains(errStr, "5.1.0") || strings.Contains(errStr, "5.4.1") {
		return true
	}

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

	var textErr *textproto.Error
	if errors.As(err, &textErr) {
		if textErr.Code == 550 || textErr.Code == 551 {
			return true
		}
	}

	return false
}

func IsRateLimitError(err error) bool {
	if err == nil {
		return false
	}
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

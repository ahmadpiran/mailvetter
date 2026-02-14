package lookup

import (
	"context"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"

	"mailvetter/internal/proxy"
)

const (
	HeloHost = "mta1.mailvetter.com"
	MailFrom = "verify@mailvetter.com"
)

// CheckSMTP performs a standard probe.
func CheckSMTP(ctx context.Context, mxHost string, targetEmail string) (bool, time.Duration, error) {
	start := time.Now()
	conn, err := proxy.DialContext(ctx, "tcp", mxHost+":25", 5*time.Second)

	if err != nil {
		return false, 0, fmt.Errorf("connection failed: %w", err)
	}

	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	client, err := smtp.NewClient(conn, host)
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

// CheckPostmaster verifies if the server accepts "postmaster@domain".
// If this fails (550), the server is non-compliant/broken.
func CheckPostmaster(ctx context.Context, mxHost, domain string) bool {
	// Re-use CheckSMTP but ignore timing
	success, _, err := CheckSMTP(ctx, mxHost, "postmaster@"+domain)

	// If success (250 OK), it's good.
	if success {
		return true
	}

	// If failed, we only care if it was a "User Unknown" (550) error.
	// A connection timeout doesn't mean "Broken", it means "Down".
	// A 550 means "I am configured incorrectly".
	if IsNoSuchUserError(err) {
		return false // Broken!
	}

	return true // Assume valid if other error (greylist/timeout) to be safe
}

// CheckVRFY attempts to verify the user using the VRFY command.
func CheckVRFY(ctx context.Context, mxHost string, targetEmail string) bool {
	conn, err := proxy.DialContext(ctx, "tcp", mxHost+":25", 4*time.Second)

	if err != nil {
		return false
	}
	defer conn.Close()

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

// Helpers
func IsNoSuchUserError(err error) bool {
	if err == nil {
		return false
	}
	if textErr, ok := err.(*textproto.Error); ok {
		return textErr.Code == 550
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "550") || strings.Contains(s, "user unknown") || strings.Contains(s, "does not exist")
}

func IsGreylisted(err error) bool {
	if err == nil {
		return false
	}
	if textErr, ok := err.(*textproto.Error); ok {
		return textErr.Code == 451 || textErr.Code == 450
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "451") || strings.Contains(s, "greylist") || strings.Contains(s, "try again later")
}

func IsSoftBounce(err error) bool {
	if err == nil {
		return false
	}
	if textErr, ok := err.(*textproto.Error); ok {
		return textErr.Code == 452
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "quota") || strings.Contains(s, "full")
}

package lib

import (
	"errors"
	"fmt"
	"html"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/beego/beego/v2/core/logs"
	gomail "gopkg.in/gomail.v2"
)

// SMTPConfig holds SMTP settings read from the environment.
type SMTPConfig struct {
	Host       string
	Port       int
	User       string
	Password   string
	From       string
	FromName   string
	Encryption string // none | ssl | starttls
}

// LoadSMTPConfig reads SMTP settings from environment variables. Host, Port and
// From are required; the rest are optional. Encryption defaults to "starttls".
func LoadSMTPConfig() (SMTPConfig, error) {
	cfg := SMTPConfig{
		Host:       strings.TrimSpace(os.Getenv("SMTP_HOST")),
		User:       os.Getenv("SMTP_USER"),
		Password:   os.Getenv("SMTP_PASSWORD"),
		From:       strings.TrimSpace(os.Getenv("SMTP_FROM")),
		FromName:   os.Getenv("SMTP_FROM_NAME"),
		Encryption: strings.ToLower(strings.TrimSpace(os.Getenv("SMTP_ENCRYPTION"))),
	}
	if cfg.FromName == "" {
		cfg.FromName = "OpenVPN"
	}
	if cfg.Encryption == "" {
		cfg.Encryption = "starttls"
	}

	if cfg.Host == "" {
		return cfg, errors.New("SMTP is not configured: SMTP_HOST is empty")
	}
	if cfg.From == "" {
		return cfg, errors.New("SMTP is not configured: SMTP_FROM is empty")
	}
	portStr := strings.TrimSpace(os.Getenv("SMTP_PORT"))
	if portStr == "" {
		return cfg, errors.New("SMTP is not configured: SMTP_PORT is empty")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return cfg, fmt.Errorf("invalid SMTP_PORT %q", portStr)
	}
	cfg.Port = port

	switch cfg.Encryption {
	case "none", "ssl", "starttls":
	default:
		return cfg, fmt.Errorf("invalid SMTP_ENCRYPTION %q (want none|ssl|starttls)", cfg.Encryption)
	}

	return cfg, nil
}

// ClientMail describes one client-config email to send.
type ClientMail struct {
	To         string // recipient email
	ClientName string
	OVPNPath   string // path to the .ovpn attachment
	Has2FA     bool
	QRPath     string // path to the <name>.png QR image (when Has2FA)
	OTPSecret  string // Base32 secret (when Has2FA)
	OTPAuthURL string // otpauth:// URL (when Has2FA)
}

// SendClientConfigEmail sends the VPN client configuration (and, for 2FA users,
// the OTP QR code and secret) to the user via SMTP.
func SendClientConfigEmail(cfg SMTPConfig, m ClientMail) error {
	if m.To == "" {
		return errors.New("recipient email is empty")
	}

	msg := gomail.NewMessage()
	msg.SetAddressHeader("From", cfg.From, cfg.FromName)
	msg.SetHeader("To", m.To)
	msg.SetHeader("Subject", fmt.Sprintf("Your OpenVPN configuration: %s", m.ClientName))

	if _, err := os.Stat(m.OVPNPath); err != nil {
		return fmt.Errorf("ovpn file not found: %w", err)
	}
	msg.Attach(m.OVPNPath)

	var body strings.Builder
	body.WriteString(fmt.Sprintf("<p>Hello,</p><p>Your OpenVPN profile <b>%s</b> is attached as <code>%s.ovpn</code>.</p>",
		html.EscapeString(m.ClientName), html.EscapeString(m.ClientName)))

	if m.Has2FA {
		body.WriteString("<p>This account is protected by two-factor authentication (2FA). " +
			"Scan the QR code below with Google Authenticator (or a compatible app), " +
			"or enter the secret key manually.</p>")
		if m.QRPath != "" {
			if _, err := os.Stat(m.QRPath); err == nil {
				msg.Embed(m.QRPath)
				body.WriteString(fmt.Sprintf(`<p><img src="cid:%s" alt="2FA QR code"></p>`, sanitizeCID(m.QRPath)))
			} else {
				logs.Warn("QR image not found for %s: %v", m.ClientName, err)
			}
		}
		if m.OTPSecret != "" {
			body.WriteString(fmt.Sprintf("<p>Secret key: <code>%s</code></p>", html.EscapeString(m.OTPSecret)))
		}
		if m.OTPAuthURL != "" {
			body.WriteString(fmt.Sprintf("<p>Setup URL: <code>%s</code></p>", html.EscapeString(m.OTPAuthURL)))
		}
	}

	msg.SetBody("text/html", body.String())

	dialer := gomail.NewDialer(cfg.Host, cfg.Port, cfg.User, cfg.Password)
	// Port 465 is implicit TLS (SMTPS) and must use SSL regardless of the
	// configured encryption. This guards against the common 465+starttls
	// misconfiguration, which otherwise hangs waiting for a plaintext greeting.
	// For 587/25 with "starttls", SSL stays false and gomail issues STARTTLS
	// when the server advertises it.
	dialer.SSL = cfg.Encryption == "ssl" || cfg.Port == 465
	if cfg.Port == 465 && cfg.Encryption != "ssl" {
		logs.Warn("SMTP port 465 requires implicit TLS; overriding SMTP_ENCRYPTION=%q to ssl", cfg.Encryption)
	}

	// Send with an overall timeout so a misconfigured or unreachable server
	// fails fast instead of blocking the request indefinitely (gomail only
	// bounds the TCP connect, not the post-connect handshake/greeting read).
	done := make(chan error, 1)
	go func() { done <- dialer.DialAndSend(msg) }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("sending email: %w", err)
		}
		return nil
	case <-time.After(20 * time.Second):
		return errors.New("sending email: timed out after 20s (check SMTP host/port/encryption)")
	}
}

// sanitizeCID derives the Content-ID gomail assigns to an embedded file, which
// is the file's base name.
func sanitizeCID(path string) string {
	i := strings.LastIndexAny(path, "/\\")
	if i >= 0 {
		return path[i+1:]
	}
	return path
}

package lib

import "testing"

func TestLoadSMTPConfig(t *testing.T) {
	t.Run("valid with defaults", func(t *testing.T) {
		t.Setenv("SMTP_HOST", "smtp.example.com")
		t.Setenv("SMTP_PORT", "587")
		t.Setenv("SMTP_FROM", "vpn@example.com")
		t.Setenv("SMTP_USER", "")
		t.Setenv("SMTP_PASSWORD", "")
		t.Setenv("SMTP_FROM_NAME", "")
		t.Setenv("SMTP_ENCRYPTION", "")

		cfg, err := LoadSMTPConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Port != 587 {
			t.Errorf("Port = %d, want 587", cfg.Port)
		}
		if cfg.FromName != "OpenVPN" {
			t.Errorf("FromName = %q, want default OpenVPN", cfg.FromName)
		}
		if cfg.Encryption != "starttls" {
			t.Errorf("Encryption = %q, want default starttls", cfg.Encryption)
		}
	})

	t.Run("missing host", func(t *testing.T) {
		t.Setenv("SMTP_HOST", "")
		t.Setenv("SMTP_PORT", "587")
		t.Setenv("SMTP_FROM", "vpn@example.com")
		if _, err := LoadSMTPConfig(); err == nil {
			t.Error("expected error for missing SMTP_HOST")
		}
	})

	t.Run("missing port", func(t *testing.T) {
		t.Setenv("SMTP_HOST", "smtp.example.com")
		t.Setenv("SMTP_PORT", "")
		t.Setenv("SMTP_FROM", "vpn@example.com")
		if _, err := LoadSMTPConfig(); err == nil {
			t.Error("expected error for missing SMTP_PORT")
		}
	})

	t.Run("bad port", func(t *testing.T) {
		t.Setenv("SMTP_HOST", "smtp.example.com")
		t.Setenv("SMTP_PORT", "abc")
		t.Setenv("SMTP_FROM", "vpn@example.com")
		if _, err := LoadSMTPConfig(); err == nil {
			t.Error("expected error for non-numeric SMTP_PORT")
		}
	})

	t.Run("bad encryption", func(t *testing.T) {
		t.Setenv("SMTP_HOST", "smtp.example.com")
		t.Setenv("SMTP_PORT", "587")
		t.Setenv("SMTP_FROM", "vpn@example.com")
		t.Setenv("SMTP_ENCRYPTION", "tls12")
		if _, err := LoadSMTPConfig(); err == nil {
			t.Error("expected error for invalid SMTP_ENCRYPTION")
		}
	})
}

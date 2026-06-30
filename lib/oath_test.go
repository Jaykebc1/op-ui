package lib

import "testing"

func TestParseUserHash(t *testing.T) {
	content := "alice@wonderland.ua:abc123hashalice\nbob@example.com:bobhash456\n"
	tests := []struct {
		name    string
		tfaName string
		want    string
		wantErr bool
	}{
		{"exact match", "bob@example.com", "bobhash456", false},
		{"case insensitive", "Alice@Wonderland.UA", "abc123hashalice", false},
		{"missing", "carol@example.com", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseUserHash(content, tt.tfaName)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseUserHashEmptySecret(t *testing.T) {
	if _, err := parseUserHash("alice@wonderland.ua:\n", "alice@wonderland.ua"); err == nil {
		t.Error("expected error for empty secret")
	}
}

func TestParseBase32(t *testing.T) {
	out := "Hex secret: 6162630a\nBase32 secret: MFRGGZA\nStart counter: 0x0\n"
	got, err := parseBase32(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "MFRGGZA" {
		t.Errorf("got %q, want MFRGGZA", got)
	}
}

func TestParseBase32Missing(t *testing.T) {
	if _, err := parseBase32("no secret here\n"); err == nil {
		t.Error("expected error when Base32 line absent")
	}
}

func TestBuildOTPAuthURL(t *testing.T) {
	got := buildOTPAuthURL("MFA%20OpenVPN-UI", "alice@wonderland.ua", "MFRGGZA")
	want := "otpauth://totp/MFA%20OpenVPN-UI:alice@wonderland.ua?secret=MFRGGZA"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

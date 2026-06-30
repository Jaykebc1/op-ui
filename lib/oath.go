package lib

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// GetOATHSecret recovers the 2FA secret for a given user so it can be re-shared
// (e.g. by email). It reads the per-user hash from clients/oath.secrets and uses
// oathtool to derive the Base32 secret, then builds the otpauth:// URL using the
// same issuer that was used at creation time.
func GetOATHSecret(ovconfigPath, tfaName, issuer string) (base32Secret, otpauthURL string, err error) {
	secretsPath := filepath.Join(ovconfigPath, "clients", "oath.secrets")
	content, err := os.ReadFile(secretsPath)
	if err != nil {
		return "", "", fmt.Errorf("reading %s: %w", secretsPath, err)
	}

	userHash, err := parseUserHash(string(content), tfaName)
	if err != nil {
		return "", "", err
	}

	out, err := exec.Command("oathtool", "--totp", "-v", userHash).CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("oathtool failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	base32Secret, err = parseBase32(string(out))
	if err != nil {
		return "", "", err
	}

	return base32Secret, buildOTPAuthURL(issuer, tfaName, base32Secret), nil
}

// parseUserHash returns the user hash for tfaName from oath.secrets content.
// Each line is "<tfaname>:<userhash>". Matching is case-insensitive and the
// first match wins, mirroring the lookup in bin/oath.sh.
func parseUserHash(content, tfaName string) (string, error) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, hash, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(name), tfaName) {
			hash = strings.TrimSpace(hash)
			if hash == "" {
				return "", fmt.Errorf("empty 2FA secret for %q", tfaName)
			}
			return hash, nil
		}
	}
	return "", fmt.Errorf("no 2FA secret found for %q", tfaName)
}

// parseBase32 extracts the Base32 secret from oathtool -v output, which contains
// a line of the form "Base32 secret: ABC234...".
func parseBase32(oathtoolOutput string) (string, error) {
	for _, line := range strings.Split(oathtoolOutput, "\n") {
		if !strings.Contains(line, "Base32") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			return fields[2], nil
		}
	}
	return "", errors.New("could not parse Base32 secret from oathtool output")
}

// buildOTPAuthURL composes the otpauth:// URL. issuer and tfaName are used as-is,
// matching genclient.sh which already passes a URL-encoded issuer (e.g.
// "MFA%20OpenVPN-UI").
func buildOTPAuthURL(issuer, tfaName, base32Secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s", issuer, tfaName, base32Secret)
}

package authn

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestServiceTokens(t *testing.T) {
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	seen := map[string]bool{}
	for _, days := range []int{0, 1, 30, 365} {
		token, record, err := GenerateServiceToken(now, days)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(token, "aops_") {
			t.Fatalf("missing prefix: %q", token)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, "aops_"))
		if err != nil || len(decoded) != 32 {
			t.Fatalf("random length=%d, err=%v", len(decoded), err)
		}
		if seen[token] {
			t.Fatal("reused token")
		}
		seen[token] = true
		if record.Hash != sha256.Sum256([]byte(token)) {
			t.Fatal("digest does not cover full token")
		}
		if days == 0 {
			days = 30
		}
		if !record.ExpiresAt.Equal(now.Add(time.Duration(days) * 24 * time.Hour)) {
			t.Fatalf("expiry: %v", record.ExpiresAt)
		}
		if !VerifyServiceToken(token, record, now) || VerifyServiceToken(token, record, record.ExpiresAt) {
			t.Fatal("validity/expiry boundary incorrect")
		}
		if VerifyServiceToken(token+"x", record, now) || VerifyServiceToken("aops_invalid", record, now) {
			t.Fatal("malformed token accepted")
		}
		record.Revoked = true
		if VerifyServiceToken(token, record, now) {
			t.Fatal("revoked token accepted")
		}
	}
	for _, days := range []int{-1, 366} {
		if _, _, err := GenerateServiceToken(now, days); err == nil {
			t.Fatalf("accepted days=%d", days)
		}
	}
}

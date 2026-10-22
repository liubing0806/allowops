package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

// GenerateServiceToken returns the secret once, separately from its persistable record.
// A zero validity selects 30 days; other values must be in [1,365].
func GenerateServiceToken(now time.Time, days int) (string, TokenRecord, error) {
	if days == 0 {
		days = 30
	}
	if days < 1 || days > 365 {
		return "", TokenRecord{}, errors.New("token validity must be 1 to 365 days")
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", TokenRecord{}, err
	}
	token := "aops_" + base64.RawURLEncoding.EncodeToString(random)
	return token, TokenRecord{Hash: sha256.Sum256([]byte(token)), ExpiresAt: now.Add(time.Duration(days) * 24 * time.Hour)}, nil
}

func VerifyServiceToken(token string, record TokenRecord, now time.Time) bool {
	hash := sha256.Sum256([]byte(token))
	matches := subtle.ConstantTimeCompare(hash[:], record.Hash[:]) == 1
	encoded := strings.TrimPrefix(token, "aops_")
	random, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	validFormat := strings.HasPrefix(token, "aops_") && err == nil && len(random) == 32
	return matches && validFormat && !record.Revoked && now.Before(record.ExpiresAt)
}

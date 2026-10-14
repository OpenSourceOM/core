// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	totpDigits = 6
	totpPeriod = 30
	totpWindow = 1
)

func newTOTPSecret() (string, error) {
	var raw [20]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:]), nil
}

// ProvisioningURI is the otpauth URL a authenticator app can import.
func ProvisioningURI(email, secret string) string {
	label := url.PathEscape("OpenSourceOM:" + email)
	values := url.Values{}
	values.Set("secret", secret)
	values.Set("issuer", "OpenSourceOM")
	values.Set("period", fmt.Sprintf("%d", totpPeriod))
	values.Set("digits", fmt.Sprintf("%d", totpDigits))
	return "otpauth://totp/" + label + "?" + values.Encode()
}

func totpMatches(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits || secret == "" {
		return false
	}
	counter := now.Unix() / totpPeriod
	matched := false
	for delta := int64(-totpWindow); delta <= totpWindow; delta++ {
		got, err := totpAt(secret, counter+delta)
		if err != nil {
			return false
		}
		if subtleConstantEquals(got, code) {
			matched = true
		}
	}
	return matched
}

func totpAt(secret string, counter int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, bin%mod), nil
}

func newRecoveryCodes() (plain []string, hashes string, err error) {
	plain = make([]string, 8)
	stored := make([]string, 8)
	for i := range plain {
		var raw [5]byte
		if _, err = rand.Read(raw[:]); err != nil {
			return nil, "", err
		}
		value := hex.EncodeToString(raw[:])
		plain[i] = value[:5] + "-" + value[5:]
		stored[i] = hashRecovery(plain[i])
	}
	return plain, strings.Join(stored, ","), nil
}

func hashRecovery(code string) string {
	sum := sha256.Sum256([]byte(normalizeRecovery(code)))
	return hex.EncodeToString(sum[:])
}

func normalizeRecovery(code string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}

func consumeRecovery(stored, code string) (string, bool) {
	want := hashRecovery(code)
	parts := strings.Split(stored, ",")
	kept := make([]string, 0, len(parts))
	found := false
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !found && subtleConstantEquals(part, want) {
			found = true
			continue
		}
		kept = append(kept, part)
	}
	if !found {
		return stored, false
	}
	return strings.Join(kept, ","), true
}

func subtleConstantEquals(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return hmac.Equal([]byte(a), []byte(b))
}

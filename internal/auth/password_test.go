// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"testing"
	"time"
)

func TestPasswordRoundTrip(t *testing.T) {
	encoded, err := HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(encoded, "correct-horse-battery") {
		t.Fatal("password did not match")
	}
	if VerifyPassword(encoded, "wrong-horse-battery") {
		t.Fatal("wrong password matched")
	}
	if err := ValidatePassword("short"); err != ErrPasswordShort {
		t.Fatalf("short password = %v", err)
	}
}

func TestTOTPVector(t *testing.T) {
	// RFC 6238 SHA1 test vector at Unix time 59.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code, err := totpAt(secret, 59/30)
	if err != nil {
		t.Fatal(err)
	}
	if code != "287082" {
		t.Fatalf("code = %s", code)
	}
	if !totpMatches(secret, "287082", time.Unix(59, 0)) {
		t.Fatal("vector did not match")
	}
}

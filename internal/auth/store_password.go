// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	loginChallengeTTL = 5 * time.Minute
	passwordResetTTL  = time.Hour
)

func (s *Store) FindByEmail(ctx context.Context, email string) (Admin, bool, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return Admin{}, false, nil
	}
	var admin Admin
	err = s.pool.QueryRow(ctx, `
		SELECT id::text, provider, subject, login, display_name, email, must_change_password, totp_enabled, created_at
		FROM admins
		WHERE lower(email) = $1
		ORDER BY CASE WHEN provider = 'password' THEN 0 ELSE 1 END, created_at
		LIMIT 1
	`, email).Scan(&admin.ID, &admin.Provider, &admin.Subject, &admin.Login, &admin.Name, &admin.Email, &admin.MustChangePassword, &admin.TOTPEnabled, &admin.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Admin{}, false, nil
	}
	if err != nil {
		return Admin{}, false, err
	}
	return admin, true, nil
}

func (s *Store) SetupAdmin(ctx context.Context, email, password, pinnedEmail string) (Admin, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return Admin{}, err
	}
	if pinnedEmail != "" {
		pinnedEmail, err = NormalizeEmail(pinnedEmail)
		if err != nil {
			return Admin{}, err
		}
		if email != pinnedEmail {
			return Admin{}, ErrSetupEmail
		}
	}
	if err := ValidatePassword(password); err != nil {
		return Admin{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Admin{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `LOCK TABLE admins IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return Admin{}, err
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM admins`).Scan(&count); err != nil {
		return Admin{}, err
	}
	if count > 0 {
		return Admin{}, ErrAdminsExist
	}
	admin, err := insertPasswordAdmin(ctx, tx, email, password, false)
	if err != nil {
		return Admin{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Admin{}, err
	}
	return admin, nil
}

func (s *Store) CreateWithPassword(ctx context.Context, email, password string, mustChange bool) (Admin, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return Admin{}, err
	}
	if err := ValidatePassword(password); err != nil {
		return Admin{}, err
	}
	return insertPasswordAdmin(ctx, s.pool, email, password, mustChange)
}

func (s *Store) ProvisionAdmin(ctx context.Context, email string) (Admin, string, error) {
	password, err := temporaryPassword()
	if err != nil {
		return Admin{}, "", err
	}
	admin, err := s.CreateWithPassword(ctx, email, password, true)
	if err != nil {
		return Admin{}, "", err
	}
	return admin, password, nil
}

func (s *Store) CheckPassword(ctx context.Context, email, password string) (Admin, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return Admin{}, ErrBadCredentials
	}
	admin, hash, err := s.passwordRecord(ctx, email)
	if err != nil {
		return Admin{}, err
	}
	if hash == "" || !VerifyPassword(hash, password) {
		return Admin{}, ErrBadCredentials
	}
	return admin, nil
}

func (s *Store) ChangePassword(ctx context.Context, adminID, current, next string) error {
	if err := ValidatePassword(next); err != nil {
		return err
	}
	var email, hash string
	err := s.pool.QueryRow(ctx, `SELECT email, password_hash FROM admins WHERE id = $1`, adminID).Scan(&email, &hash)
	if errors.Is(err, pgx.ErrNoRows) || invalidUUID(err) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if hash == "" || !VerifyPassword(hash, current) {
		return ErrBadCredentials
	}
	return s.storePassword(ctx, email, next, false)
}

func (s *Store) SetPassword(ctx context.Context, email, password string) error {
	email, err := NormalizeEmail(email)
	if err != nil {
		return err
	}
	if err := ValidatePassword(password); err != nil {
		return err
	}
	admin, found, err := s.FindByEmail(ctx, email)
	if err != nil {
		return err
	}
	if !found || admin.Provider != ProviderPassword {
		return ErrNotFound
	}
	return s.storePassword(ctx, email, password, false)
}

// RequestPasswordReset stores a one-hour token for a password admin.
// An unknown address returns an empty token and no error.
func (s *Store) RequestPasswordReset(ctx context.Context, email string) (string, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return "", nil
	}
	admin, hash, err := s.passwordRecord(ctx, email)
	if err != nil {
		return "", err
	}
	if admin.ID == "" || hash == "" {
		return "", nil
	}
	raw, err := NewToken()
	if err != nil {
		return "", err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM admin_password_resets WHERE admin_id = $1`, admin.ID); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO admin_password_resets (id, admin_id, expires_at)
		VALUES ($1, $2, $3)
	`, HashToken(raw), admin.ID, time.Now().UTC().Add(passwordResetTTL)); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return raw, nil
}

// CompletePasswordReset sets the password from a single-use token and ends that admin's sessions.
func (s *Store) CompletePasswordReset(ctx context.Context, token, password string) error {
	if err := ValidatePassword(password); err != nil {
		return err
	}
	if token == "" || len(token) > 128 {
		return ErrResetInvalid
	}
	encoded, err := HashPassword(password)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var adminID string
	var expires time.Time
	err = tx.QueryRow(ctx, `
		DELETE FROM admin_password_resets
		WHERE id = $1
		RETURNING admin_id::text, expires_at
	`, HashToken(token)).Scan(&adminID, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrResetInvalid
	}
	if err != nil {
		return err
	}
	if !expires.After(time.Now()) {
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		return ErrResetInvalid
	}
	tag, err := tx.Exec(ctx, `
		UPDATE admins
		SET password_hash = $1, must_change_password = false
		WHERE id = $2 AND provider = 'password'
	`, encoded, adminID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrResetInvalid
	}
	if _, err := tx.Exec(ctx, `DELETE FROM admin_sessions WHERE admin_id = $1`, adminID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM admin_login_challenges WHERE admin_id = $1`, adminID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM admin_password_resets WHERE admin_id = $1`, adminID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) BeginTOTP(ctx context.Context, adminID string) (string, error) {
	var enabled bool
	err := s.pool.QueryRow(ctx, `SELECT totp_enabled FROM admins WHERE id = $1`, adminID).Scan(&enabled)
	if errors.Is(err, pgx.ErrNoRows) || invalidUUID(err) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if enabled {
		return "", ErrTOTPEnabled
	}
	secret, err := newTOTPSecret()
	if err != nil {
		return "", err
	}
	_, err = s.pool.Exec(ctx, `UPDATE admins SET totp_pending = $1 WHERE id = $2`, secret, adminID)
	return secret, err
}

func (s *Store) ConfirmTOTP(ctx context.Context, adminID, code string) ([]string, error) {
	var pending, email string
	err := s.pool.QueryRow(ctx, `SELECT totp_pending, email FROM admins WHERE id = $1`, adminID).Scan(&pending, &email)
	if errors.Is(err, pgx.ErrNoRows) || invalidUUID(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if pending == "" || !totpMatches(pending, code, time.Now()) {
		return nil, ErrTOTPInvalid
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE admins
		SET totp_secret = $1, totp_pending = '', totp_enabled = true, recovery_hashes = $2
		WHERE id = $3
	`, pending, hashes, adminID)
	if err != nil {
		return nil, err
	}
	return codes, nil
}

func (s *Store) DisableTOTP(ctx context.Context, adminID, password, code string) error {
	var email, hash string
	var enabled bool
	err := s.pool.QueryRow(ctx, `
		SELECT email, password_hash, totp_enabled FROM admins WHERE id = $1
	`, adminID).Scan(&email, &hash, &enabled)
	if errors.Is(err, pgx.ErrNoRows) || invalidUUID(err) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !enabled || hash == "" || !VerifyPassword(hash, password) {
		return ErrBadCredentials
	}
	if err := s.VerifySecondFactor(ctx, adminID, code); err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE admins
		SET totp_secret = '', totp_pending = '', totp_enabled = false, recovery_hashes = ''
		WHERE id = $1
	`, adminID)
	return err
}

func (s *Store) VerifySecondFactor(ctx context.Context, adminID, code string) error {
	var secret, hashes string
	var enabled bool
	err := s.pool.QueryRow(ctx, `
		SELECT totp_secret, totp_enabled, recovery_hashes FROM admins WHERE id = $1
	`, adminID).Scan(&secret, &enabled, &hashes)
	if errors.Is(err, pgx.ErrNoRows) || invalidUUID(err) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !enabled {
		return ErrTOTPInvalid
	}
	if totpMatches(secret, code, time.Now()) {
		return nil
	}
	next, ok := consumeRecovery(hashes, code)
	if !ok {
		return ErrTOTPInvalid
	}
	_, err = s.pool.Exec(ctx, `UPDATE admins SET recovery_hashes = $1 WHERE id = $2`, next, adminID)
	return err
}

func (s *Store) CreateLoginChallenge(ctx context.Context, adminID string) (string, error) {
	raw, err := NewToken()
	if err != nil {
		return "", err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO admin_login_challenges (id, admin_id, expires_at)
		VALUES ($1, $2, $3)
	`, HashToken(raw), adminID, time.Now().UTC().Add(loginChallengeTTL))
	if invalidUUID(err) {
		return "", ErrNotFound
	}
	return raw, err
}

func (s *Store) ConsumeLoginChallenge(ctx context.Context, token string) (Admin, error) {
	if token == "" || len(token) > 128 {
		return Admin{}, ErrNotFound
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Admin{}, err
	}
	defer tx.Rollback(ctx)
	var admin Admin
	var expires time.Time
	err = tx.QueryRow(ctx, `
		DELETE FROM admin_login_challenges
		WHERE id = $1
		RETURNING admin_id::text, expires_at
	`, HashToken(token)).Scan(&admin.ID, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return Admin{}, ErrNotFound
	}
	if err != nil {
		return Admin{}, err
	}
	if !expires.After(time.Now()) {
		if err := tx.Commit(ctx); err != nil {
			return Admin{}, err
		}
		return Admin{}, ErrNotFound
	}
	err = tx.QueryRow(ctx, `
		SELECT id::text, provider, subject, login, display_name, email, must_change_password, totp_enabled, created_at
		FROM admins WHERE id = $1
	`, admin.ID).Scan(&admin.ID, &admin.Provider, &admin.Subject, &admin.Login, &admin.Name, &admin.Email, &admin.MustChangePassword, &admin.TOTPEnabled, &admin.CreatedAt)
	if err != nil {
		return Admin{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Admin{}, err
	}
	return admin, nil
}

func (s *Store) passwordRecord(ctx context.Context, email string) (Admin, string, error) {
	var admin Admin
	var hash string
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, provider, subject, login, display_name, email, must_change_password, totp_enabled, created_at, password_hash
		FROM admins
		WHERE provider = 'password' AND lower(email) = $1
	`, email).Scan(&admin.ID, &admin.Provider, &admin.Subject, &admin.Login, &admin.Name, &admin.Email, &admin.MustChangePassword, &admin.TOTPEnabled, &admin.CreatedAt, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return Admin{}, "", nil
	}
	if err != nil {
		return Admin{}, "", err
	}
	return admin, hash, nil
}

func (s *Store) storePassword(ctx context.Context, email, password string, mustChange bool) error {
	encoded, err := HashPassword(password)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE admins
		SET password_hash = $1, must_change_password = $2
		WHERE provider = 'password' AND lower(email) = $3
	`, encoded, mustChange, email)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

type passwordWriter interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func insertPasswordAdmin(ctx context.Context, q passwordWriter, email, password string, mustChange bool) (Admin, error) {
	encoded, err := HashPassword(password)
	if err != nil {
		return Admin{}, err
	}
	var admin Admin
	err = q.QueryRow(ctx, `
		INSERT INTO admins (
			provider, subject, login, display_name, email,
			password_hash, must_change_password
		)
		VALUES ('password', $1, $1, '', $1, $2, $3)
		RETURNING id::text, provider, subject, login, display_name, email, must_change_password, totp_enabled, created_at
	`, email, encoded, mustChange).Scan(
		&admin.ID, &admin.Provider, &admin.Subject, &admin.Login, &admin.Name, &admin.Email, &admin.MustChangePassword, &admin.TOTPEnabled, &admin.CreatedAt,
	)
	if uniqueViolation(err) {
		return Admin{}, ErrEmailTaken
	}
	return admin, err
}

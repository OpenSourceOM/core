// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store persists admins, email invites, sessions, and personal API tokens.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

func (s *Store) Count(ctx context.Context) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM admins`).Scan(&count)
	return count, err
}

func (s *Store) List(ctx context.Context) ([]Admin, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, provider, subject, login, display_name, email, must_change_password, totp_enabled, created_at
		FROM admins
		ORDER BY created_at ASC, id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var admins []Admin
	for rows.Next() {
		admin, err := scanAdmin(rows)
		if err != nil {
			return nil, err
		}
		admins = append(admins, admin)
	}
	if admins == nil {
		admins = []Admin{}
	}
	return admins, rows.Err()
}

func (s *Store) Delete(ctx context.Context, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `LOCK TABLE admins IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM admins`).Scan(&count); err != nil {
		return err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM admins WHERE id = $1)`, id).Scan(&exists); err != nil {
		if invalidUUID(err) {
			return ErrNotFound
		}
		return err
	}
	if !exists {
		return ErrNotFound
	}
	if count < 2 {
		return ErrLastAdmin
	}
	if _, err := tx.Exec(ctx, `DELETE FROM admins WHERE id = $1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) Find(ctx context.Context, provider, subject string) (Admin, bool, error) {
	return findAdmin(ctx, s.pool, provider, subject)
}

func (s *Store) CreateSession(ctx context.Context, adminID string) (string, time.Time, error) {
	raw, err := NewToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expires := time.Now().UTC().Add(sessionTTL)
	_, err = s.pool.Exec(ctx, `
		INSERT INTO admin_sessions (id, admin_id, expires_at)
		VALUES ($1, $2, $3)
	`, HashToken(raw), adminID, expires)
	if invalidUUID(err) {
		return "", time.Time{}, ErrNotFound
	}
	if err != nil {
		return "", time.Time{}, err
	}
	return raw, expires, nil
}

func (s *Store) DeleteSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return nil
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM admin_sessions WHERE id = $1`, HashToken(sessionID))
	return err
}

func (s *Store) AdminForSession(ctx context.Context, sessionID string) (Admin, error) {
	if sessionID == "" {
		return Admin{}, ErrNotFound
	}
	var admin Admin
	var expires time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT a.id::text, a.provider, a.subject, a.login, a.display_name, a.email, a.must_change_password, a.totp_enabled, a.created_at, s.expires_at
		FROM admin_sessions s
		JOIN admins a ON a.id = s.admin_id
		WHERE s.id = $1
	`, HashToken(sessionID)).Scan(&admin.ID, &admin.Provider, &admin.Subject, &admin.Login, &admin.Name, &admin.Email, &admin.MustChangePassword, &admin.TOTPEnabled, &admin.CreatedAt, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return Admin{}, ErrNotFound
	}
	if err != nil {
		return Admin{}, err
	}
	if !expires.After(time.Now()) {
		_ = s.DeleteSession(ctx, sessionID)
		return Admin{}, ErrNotFound
	}
	return admin, nil
}

func (s *Store) CreateInvite(ctx context.Context, createdBy, email string) (string, time.Time, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return "", time.Time{}, err
	}
	raw, err := NewToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expires := time.Now().UTC().Add(inviteTTL)
	_, err = s.pool.Exec(ctx, `
		INSERT INTO admin_invites (token_hash, created_by, expires_at, email)
		VALUES ($1, $2, $3, $4)
	`, HashToken(raw), createdBy, expires, email)
	if invalidUUID(err) {
		return "", time.Time{}, ErrNotFound
	}
	if err != nil {
		return "", time.Time{}, err
	}
	return raw, expires, nil
}

func (s *Store) DiscardInvite(ctx context.Context, token string) error {
	hash, err := inviteToken(token)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		DELETE FROM admin_invites
		WHERE token_hash = $1 AND consumed_at IS NULL
	`, hash)
	return err
}

func (s *Store) Bootstrap(ctx context.Context, identity Identity) (Admin, error) {
	identity, err := identity.normalized()
	if err != nil {
		return Admin{}, err
	}
	if len(identity.Emails) == 0 {
		return Admin{}, ErrEmailUnverified
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
	existing, found, err := findAdmin(ctx, tx, identity.Provider, identity.Subject)
	if err != nil {
		return Admin{}, err
	}
	if found {
		if err := tx.Commit(ctx); err != nil {
			return Admin{}, err
		}
		return existing, nil
	}
	admin, err := insertAdmin(ctx, tx, identity, identity.Emails[0])
	if err != nil {
		return Admin{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Admin{}, err
	}
	return admin, nil
}

func (s *Store) AdminForToken(ctx context.Context, token string) (Admin, error) {
	if token == "" || len(token) > 128 {
		return Admin{}, ErrNotFound
	}
	var admin Admin
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, provider, subject, login, display_name, email, must_change_password, totp_enabled, created_at
		FROM admins
		WHERE api_token_hash = $1
	`, HashToken(token)).Scan(&admin.ID, &admin.Provider, &admin.Subject, &admin.Login, &admin.Name, &admin.Email, &admin.MustChangePassword, &admin.TOTPEnabled, &admin.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Admin{}, ErrNotFound
	}
	if err != nil {
		return Admin{}, err
	}
	return admin, nil
}

func (s *Store) TakeTokenPreview(ctx context.Context, adminID string) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	var preview *string
	err = tx.QueryRow(ctx, `
		SELECT api_token_preview FROM admins WHERE id = $1 FOR UPDATE
	`, adminID).Scan(&preview)
	if errors.Is(err, pgx.ErrNoRows) || invalidUUID(err) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if preview == nil || *preview == "" {
		if err := tx.Commit(ctx); err != nil {
			return "", err
		}
		return "", nil
	}
	if _, err := tx.Exec(ctx, `UPDATE admins SET api_token_preview = NULL WHERE id = $1`, adminID); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return *preview, nil
}

func (s *Store) RotateToken(ctx context.Context, adminID string) (string, error) {
	raw, err := NewToken()
	if err != nil {
		return "", err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE admins
		SET api_token_hash = $1, api_token_preview = NULL
		WHERE id = $2
	`, HashToken(raw), adminID)
	if invalidUUID(err) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() == 0 {
		return "", ErrNotFound
	}
	return raw, nil
}

func (s *Store) PeekInvite(ctx context.Context, token string) error {
	hash, err := inviteToken(token)
	if err != nil {
		return err
	}
	var expires time.Time
	var consumed *time.Time
	err = s.pool.QueryRow(ctx, `
		SELECT expires_at, consumed_at
		FROM admin_invites
		WHERE token_hash = $1
	`, hash).Scan(&expires, &consumed)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInviteInvalid
	}
	if err != nil {
		return err
	}
	return inviteState(expires, consumed)
}

func (s *Store) AcceptInvite(ctx context.Context, token string, identity Identity) (Admin, error) {
	identity, err := identity.normalized()
	if err != nil {
		return Admin{}, err
	}
	hash, err := inviteToken(token)
	if err != nil {
		return Admin{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Admin{}, err
	}
	defer tx.Rollback(ctx)

	// Same lock order as Bootstrap and Delete: admins, then the invite row.
	if _, err := tx.Exec(ctx, `LOCK TABLE admins IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return Admin{}, err
	}
	var expires time.Time
	var consumed *time.Time
	var email *string
	err = tx.QueryRow(ctx, `
		SELECT expires_at, consumed_at, email
		FROM admin_invites
		WHERE token_hash = $1
		FOR UPDATE
	`, hash).Scan(&expires, &consumed, &email)
	if errors.Is(err, pgx.ErrNoRows) {
		return Admin{}, ErrInviteInvalid
	}
	if err != nil {
		return Admin{}, err
	}
	if err := inviteState(expires, consumed); err != nil {
		return Admin{}, err
	}
	invited := ""
	if email != nil {
		invited = *email
	}
	if invited == "" {
		return Admin{}, ErrInviteInvalid
	}
	if !identity.hasEmail(invited) {
		return Admin{}, ErrEmailMismatch
	}

	existing, found, err := findAdmin(ctx, tx, identity.Provider, identity.Subject)
	if err != nil {
		return Admin{}, err
	}
	if found {
		if err := tx.Commit(ctx); err != nil {
			return Admin{}, err
		}
		return existing, nil
	}

	if _, err := tx.Exec(ctx, `SAVEPOINT before_admin`); err != nil {
		return Admin{}, err
	}
	admin, err := insertAdmin(ctx, tx, identity, invited)
	if uniqueViolation(err) {
		if _, rollErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT before_admin`); rollErr != nil {
			return Admin{}, rollErr
		}
		existing, found, err = findAdmin(ctx, tx, identity.Provider, identity.Subject)
		if err != nil {
			return Admin{}, err
		}
		if !found {
			return Admin{}, ErrInviteInvalid
		}
		if err := tx.Commit(ctx); err != nil {
			return Admin{}, err
		}
		return existing, nil
	}
	if err != nil {
		return Admin{}, err
	}

	tag, err := tx.Exec(ctx, `
		UPDATE admin_invites
		SET consumed_at = now(), consumed_by = $2
		WHERE token_hash = $1 AND consumed_at IS NULL
	`, hash, admin.ID)
	if err != nil {
		return Admin{}, err
	}
	if tag.RowsAffected() != 1 {
		return Admin{}, ErrInviteUsed
	}
	if err := tx.Commit(ctx); err != nil {
		return Admin{}, err
	}
	return admin, nil
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func findAdmin(ctx context.Context, q querier, provider, subject string) (Admin, bool, error) {
	var admin Admin
	err := q.QueryRow(ctx, `
		SELECT id::text, provider, subject, login, display_name, email, must_change_password, totp_enabled, created_at
		FROM admins
		WHERE provider = $1 AND subject = $2
	`, provider, subject).Scan(&admin.ID, &admin.Provider, &admin.Subject, &admin.Login, &admin.Name, &admin.Email, &admin.MustChangePassword, &admin.TOTPEnabled, &admin.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Admin{}, false, nil
	}
	if err != nil {
		return Admin{}, false, err
	}
	return admin, true, nil
}

func insertAdmin(ctx context.Context, q querier, identity Identity, email string) (Admin, error) {
	raw, err := NewToken()
	if err != nil {
		return Admin{}, err
	}
	if email == "" && len(identity.Emails) > 0 {
		email = identity.Emails[0]
	}
	var admin Admin
	err = q.QueryRow(ctx, `
		INSERT INTO admins (provider, subject, login, display_name, email, api_token_hash, api_token_preview)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id::text, provider, subject, login, display_name, email, must_change_password, totp_enabled, created_at
	`, identity.Provider, identity.Subject, identity.Login, identity.Name, email, HashToken(raw), raw).Scan(
		&admin.ID, &admin.Provider, &admin.Subject, &admin.Login, &admin.Name, &admin.Email, &admin.MustChangePassword, &admin.TOTPEnabled, &admin.CreatedAt,
	)
	return admin, err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanAdmin(row scanner) (Admin, error) {
	var admin Admin
	err := row.Scan(&admin.ID, &admin.Provider, &admin.Subject, &admin.Login, &admin.Name, &admin.Email, &admin.MustChangePassword, &admin.TOTPEnabled, &admin.CreatedAt)
	return admin, err
}

func inviteState(expires time.Time, consumed *time.Time) error {
	if consumed != nil {
		return ErrInviteUsed
	}
	if !expires.After(time.Now()) {
		return ErrInviteExpired
	}
	return nil
}

func invalidUUID(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "22P02"
}

func uniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

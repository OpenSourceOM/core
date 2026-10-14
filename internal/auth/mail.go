// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// InviteMailer sends admin invite links over SMTP.
type InviteMailer struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

func (m InviteMailer) Enabled() bool {
	return strings.TrimSpace(m.Host) != "" && strings.TrimSpace(m.From) != "" && m.Port > 0
}

func (m InviteMailer) SendTemporaryPassword(ctx context.Context, to, password, loginURL string) error {
	to, err := NormalizeEmail(to)
	if err != nil {
		return err
	}
	body := fmt.Sprintf(
		"To: %s\r\nFrom: %s\r\nSubject: OpenSourceOM admin account\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nAn admin created an OpenSourceOM account for %s.\r\n\r\nSign in at %s\r\nTemporary password: %s\r\n\r\nYou will choose a new password at the next sign-in.\r\n",
		to, m.From, to, loginURL, password,
	)
	return m.deliver(ctx, to, body)
}

func (m InviteMailer) SendPasswordReset(ctx context.Context, to, resetURL string) error {
	to, err := NormalizeEmail(to)
	if err != nil {
		return err
	}
	body := fmt.Sprintf(
		"To: %s\r\nFrom: %s\r\nSubject: Reset your OpenSourceOM password\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nA password reset was requested for %s.\r\n\r\nOpen this link to choose a new password. It works once and expires in one hour:\r\n%s\r\n\r\nIf you did not request this, you can ignore this email.\r\n",
		to, m.From, to, resetURL,
	)
	return m.deliver(ctx, to, body)
}

func (m InviteMailer) deliver(ctx context.Context, to, body string) error {
	if !m.Enabled() {
		return fmt.Errorf("smtp is not configured")
	}

	addr := net.JoinHostPort(m.Host, strconv.Itoa(m.Port))
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	var client *smtp.Client
	if m.Port == 465 {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: m.Host})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return err
		}
		client, err = smtp.NewClient(tlsConn, m.Host)
	} else {
		client, err = smtp.NewClient(conn, m.Host)
	}
	if err != nil {
		return err
	}
	defer client.Close()

	if m.Port != 465 {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: m.Host}); err != nil {
				return err
			}
		} else if m.Username != "" {
			return fmt.Errorf("smtp server did not offer STARTTLS")
		}
	}
	if m.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", m.Username, m.Password, m.Host)); err != nil {
			return err
		}
	}
	if err := client.Mail(m.From); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write([]byte(body)); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

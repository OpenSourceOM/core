// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	loginFailureLimit = 8
	loginLockout      = 15 * time.Minute
)

type loginLimiter struct {
	mu       sync.Mutex
	failures map[string]loginFailures
}

type loginFailures struct {
	count  int
	locked time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{failures: map[string]loginFailures{}}
}

func (s *Server) tooManyAttempts(r *http.Request, key string) bool {
	if s.loginLimit == nil {
		return false
	}
	return s.loginLimit.blocked(limitKey(r, key), time.Now())
}

func (s *Server) noteFailure(r *http.Request, key string) {
	if s.loginLimit == nil {
		return
	}
	s.loginLimit.fail(limitKey(r, key), time.Now())
}

func (s *Server) clearFailures(key string) {
	if s.loginLimit == nil {
		return
	}
	s.loginLimit.clear(strings.ToLower(strings.TrimSpace(key)))
}

func limitKey(r *http.Request, key string) string {
	host, _, _ := strings.Cut(r.RemoteAddr, ":")
	return strings.ToLower(strings.TrimSpace(key)) + "|" + host
}

func (l *loginLimiter) blocked(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	state := l.failures[key]
	return !state.locked.IsZero() && state.locked.After(now)
}

func (l *loginLimiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	state := l.failures[key]
	if !state.locked.IsZero() && !state.locked.After(now) {
		state = loginFailures{}
	}
	state.count++
	if state.count >= loginFailureLimit {
		state.locked = now.Add(loginLockout)
		state.count = 0
	}
	l.failures[key] = state
}

func (l *loginLimiter) clear(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for existing := range l.failures {
		if strings.HasPrefix(existing, key+"|") || existing == key {
			delete(l.failures, existing)
		}
	}
}

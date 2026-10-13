package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenSourceOM/core/internal/auth"
)

func TestConsoleLoginCreatesAdminSession(t *testing.T) {
	directory := newMemoryDirectory()
	var sentTo, sentLink string
	provider := fakeProvider{identity: auth.Identity{Provider: auth.ProviderGitHub, Subject: "7", Login: "ada", Name: "Ada", Emails: []string{"ada@example.com"}}}
	server := NewServer(nil).WithConsoleAuth(ConsoleAuth{
		Directory: directory,
		PublicURL: "http://localhost:8080",
		Providers: map[string]auth.Provider{auth.ProviderGitHub: provider},
		SendInvite: func(_ context.Context, to, link string) error {
			sentTo, sentLink = to, link
			return nil
		},
	})
	handler := server.Handler()

	start := httptest.NewRequest(http.MethodGet, "/auth/github/start", nil)
	startRec := httptest.NewRecorder()
	handler.ServeHTTP(startRec, start)
	if startRec.Code != http.StatusFound {
		t.Fatalf("start status = %d", startRec.Code)
	}
	oauth := startRec.Result().Cookies()
	state := stateFromRedirect(t, startRec.Header().Get("Location"))
	if cookieNamed(oauth, oauthCookie).Secure {
		t.Fatal("http public URL set a Secure cookie")
	}

	callback := httptest.NewRequest(http.MethodGet, "/auth/github/callback?code=abc&state="+url.QueryEscape(state), nil)
	callback.AddCookie(cookieNamed(oauth, oauthCookie))
	callbackRec := httptest.NewRecorder()
	handler.ServeHTTP(callbackRec, callback)
	if callbackRec.Code != http.StatusFound || callbackRec.Header().Get("Location") != "/" {
		t.Fatalf("callback = %d %s", callbackRec.Code, callbackRec.Header().Get("Location"))
	}
	session := cookieNamed(callbackRec.Result().Cookies(), sessionCookie)
	if session == nil || session.Value == "" || !session.HttpOnly {
		t.Fatal("missing session cookie")
	}

	rules := httptest.NewRequest(http.MethodGet, "/v1/rules", nil)
	rules.AddCookie(session)
	rulesRec := httptest.NewRecorder()
	handler.ServeHTTP(rulesRec, rules)
	if rulesRec.Code != http.StatusOK {
		t.Fatalf("session rules status = %d", rulesRec.Code)
	}

	sessionProbe := httptest.NewRequest(http.MethodGet, "/v1/auth/session", nil)
	sessionProbe.AddCookie(session)
	sessionRec := httptest.NewRecorder()
	handler.ServeHTTP(sessionRec, sessionProbe)
	if sessionRec.Code != http.StatusOK || !strings.Contains(sessionRec.Body.String(), `"api_token"`) {
		t.Fatalf("session = %d %s", sessionRec.Code, sessionRec.Body.String())
	}

	keyOnly := httptest.NewRequest(http.MethodPost, "/v1/admins/invites", strings.NewReader(`{"email":"next@example.com"}`))
	keyOnly.Header.Set("X-API-Key", directory.rawToken())
	keyRec := httptest.NewRecorder()
	handler.ServeHTTP(keyRec, keyOnly)
	if keyRec.Code != http.StatusUnauthorized {
		t.Fatalf("api token invite status = %d", keyRec.Code)
	}

	rulesToken := httptest.NewRequest(http.MethodGet, "/v1/rules", nil)
	rulesToken.Header.Set("Authorization", "Bearer "+directory.rawToken())
	rulesTokenRec := httptest.NewRecorder()
	handler.ServeHTTP(rulesTokenRec, rulesToken)
	if rulesTokenRec.Code != http.StatusOK {
		t.Fatalf("token rules status = %d", rulesTokenRec.Code)
	}

	invite := httptest.NewRequest(http.MethodPost, "/v1/admins/invites", strings.NewReader(`{"email":"next@example.com"}`))
	invite.Header.Set("Content-Type", "application/json")
	invite.AddCookie(session)
	inviteRec := httptest.NewRecorder()
	handler.ServeHTTP(inviteRec, invite)
	if inviteRec.Code != http.StatusCreated {
		t.Fatalf("invite status = %d body %s", inviteRec.Code, inviteRec.Body.String())
	}
	if sentTo != "next@example.com" || !strings.HasPrefix(sentLink, "http://localhost:8080/invite/") {
		t.Fatalf("sent %s %s", sentTo, sentLink)
	}

	list := httptest.NewRequest(http.MethodGet, "/v1/admins", nil)
	list.AddCookie(session)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, list)
	if listRec.Code != http.StatusOK || !strings.Contains(listRec.Body.String(), `"login":"ada"`) {
		t.Fatalf("list = %d %s", listRec.Code, listRec.Body.String())
	}

	remove := httptest.NewRequest(http.MethodDelete, "/v1/admins/"+directory.onlyID(), nil)
	remove.AddCookie(session)
	removeRec := httptest.NewRecorder()
	handler.ServeHTTP(removeRec, remove)
	if removeRec.Code != http.StatusConflict {
		t.Fatalf("delete last = %d", removeRec.Code)
	}
}

func TestConsoleLoginRejectsUnknownAccount(t *testing.T) {
	directory := newMemoryDirectory()
	directory.seed(auth.Admin{ID: "admin-1", Provider: auth.ProviderGoogle, Subject: "known", Login: "known@example.com"})
	provider := fakeProvider{identity: auth.Identity{Provider: auth.ProviderGitHub, Subject: "9", Login: "stranger"}}
	handler := NewServer(nil).WithConsoleAuth(ConsoleAuth{
		Directory: directory,
		PublicURL: "https://om.example",
		Providers: map[string]auth.Provider{auth.ProviderGitHub: provider},
	}).Handler()

	start := httptest.NewRequest(http.MethodGet, "/auth/github/start", nil)
	startRec := httptest.NewRecorder()
	handler.ServeHTTP(startRec, start)
	if !cookieNamed(startRec.Result().Cookies(), oauthCookie).Secure {
		t.Fatal("https public URL did not set a Secure cookie")
	}
	state := stateFromRedirect(t, startRec.Header().Get("Location"))
	callback := httptest.NewRequest(http.MethodGet, "/auth/github/callback?code=abc&state="+url.QueryEscape(state), nil)
	callback.AddCookie(cookieNamed(startRec.Result().Cookies(), oauthCookie))
	callbackRec := httptest.NewRecorder()
	handler.ServeHTTP(callbackRec, callback)
	if callbackRec.Code != http.StatusFound || !strings.Contains(callbackRec.Header().Get("Location"), "error=not_admin") {
		t.Fatalf("callback = %d %s", callbackRec.Code, callbackRec.Header().Get("Location"))
	}
}

func TestAuthSessionStaysOpen(t *testing.T) {
	handler := (&Server{}).Handler()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/auth/session", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	login := httptest.NewRecorder()
	handler.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/login", nil))
	if login.Code != http.StatusOK || !strings.Contains(login.Body.String(), "OpenSourceOM") {
		t.Fatalf("login page = %d", login.Code)
	}
}

type fakeProvider struct {
	identity auth.Identity
}

func (f fakeProvider) Name() string { return f.identity.Provider }

func (f fakeProvider) AuthCodeURL(state, redirectURL string) string {
	return "https://id.example/auth?state=" + url.QueryEscape(state) + "&redirect_uri=" + url.QueryEscape(redirectURL)
}

func (f fakeProvider) Exchange(context.Context, string, string) (auth.Identity, error) {
	return f.identity, nil
}

type memoryDirectory struct {
	mu         sync.Mutex
	admins     []auth.Admin
	invites    map[string]memoryInvite
	sessions   map[string]string
	tokens     map[string]string
	previews   map[string]string
	plainToken string
}

type memoryInvite struct {
	expires  time.Time
	consumed bool
	email    string
}

func newMemoryDirectory() *memoryDirectory {
	return &memoryDirectory{
		invites:  map[string]memoryInvite{},
		sessions: map[string]string{},
		tokens:   map[string]string{},
		previews: map[string]string{},
	}
}

func (d *memoryDirectory) rawToken() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.plainToken
}

func (d *memoryDirectory) rememberToken(raw string, admin auth.Admin) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tokens[auth.HashToken(raw)] = admin.ID
	d.plainToken = raw
	found := false
	for _, existing := range d.admins {
		if existing.ID == admin.ID {
			found = true
			break
		}
	}
	if !found {
		d.admins = append(d.admins, admin)
	}
}

func (d *memoryDirectory) addInvite(createdBy string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	token := "invite-" + createdBy + "token"
	if createdBy == "" {
		token = "bootstrap-token"
	}
	d.invites[auth.HashToken(token)] = memoryInvite{expires: time.Now().Add(time.Hour)}
	return token
}

func (d *memoryDirectory) seed(admin auth.Admin) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.admins = append(d.admins, admin)
}

func (d *memoryDirectory) onlyID() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.admins[0].ID
}

func (d *memoryDirectory) Count(context.Context) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.admins), nil
}

func (d *memoryDirectory) List(context.Context) ([]auth.Admin, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := append([]auth.Admin(nil), d.admins...)
	return out, nil
}

func (d *memoryDirectory) Delete(_ context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.admins) < 2 {
		for _, admin := range d.admins {
			if admin.ID == id {
				return auth.ErrLastAdmin
			}
		}
		return auth.ErrNotFound
	}
	for i, admin := range d.admins {
		if admin.ID == id {
			d.admins = append(d.admins[:i], d.admins[i+1:]...)
			return nil
		}
	}
	return auth.ErrNotFound
}

func (d *memoryDirectory) Find(_ context.Context, provider, subject string) (auth.Admin, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, admin := range d.admins {
		if admin.Provider == provider && admin.Subject == subject {
			return admin, true, nil
		}
	}
	return auth.Admin{}, false, nil
}

func (d *memoryDirectory) CreateSession(_ context.Context, adminID string) (string, time.Time, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sessions[auth.HashToken("session-"+adminID)] = adminID
	return "session-" + adminID, time.Now().Add(time.Hour), nil
}

func (d *memoryDirectory) DeleteSession(_ context.Context, sessionID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.sessions, auth.HashToken(sessionID))
	return nil
}

func (d *memoryDirectory) AdminForSession(_ context.Context, sessionID string) (auth.Admin, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	id, ok := d.sessions[auth.HashToken(sessionID)]
	if !ok {
		return auth.Admin{}, auth.ErrNotFound
	}
	for _, admin := range d.admins {
		if admin.ID == id {
			return admin, nil
		}
	}
	return auth.Admin{}, auth.ErrNotFound
}

func (d *memoryDirectory) CreateInvite(_ context.Context, createdBy, email string) (string, time.Time, error) {
	email, err := auth.NormalizeEmail(email)
	if err != nil {
		return "", time.Time{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	token := "invite-" + createdBy + "-" + email
	d.invites[auth.HashToken(token)] = memoryInvite{expires: time.Now().Add(time.Hour), email: email}
	return token, time.Now().Add(time.Hour), nil
}

func (d *memoryDirectory) DiscardInvite(_ context.Context, token string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.invites, auth.HashToken(token))
	return nil
}

func (d *memoryDirectory) Bootstrap(_ context.Context, identity auth.Identity) (auth.Admin, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.admins) > 0 {
		return auth.Admin{}, auth.ErrAdminsExist
	}
	admin := auth.Admin{
		ID:       "admin-created",
		Provider: identity.Provider,
		Subject:  identity.Subject,
		Login:    identity.Login,
		Name:     identity.Name,
		Email:    identity.Emails[0],
	}
	d.admins = append(d.admins, admin)
	d.plainToken = "personal-token"
	d.tokens[auth.HashToken(d.plainToken)] = admin.ID
	d.previews[admin.ID] = d.plainToken
	return admin, nil
}

func (d *memoryDirectory) AdminForToken(_ context.Context, token string) (auth.Admin, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	id, ok := d.tokens[auth.HashToken(token)]
	if !ok {
		return auth.Admin{}, auth.ErrNotFound
	}
	for _, admin := range d.admins {
		if admin.ID == id {
			return admin, nil
		}
	}
	return auth.Admin{}, auth.ErrNotFound
}

func (d *memoryDirectory) TakeTokenPreview(_ context.Context, adminID string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	preview := d.previews[adminID]
	delete(d.previews, adminID)
	return preview, nil
}

func (d *memoryDirectory) RotateToken(_ context.Context, adminID string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.plainToken = "rotated-token"
	d.tokens[auth.HashToken(d.plainToken)] = adminID
	return d.plainToken, nil
}

func (d *memoryDirectory) PeekInvite(_ context.Context, token string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	invite, ok := d.invites[auth.HashToken(token)]
	if !ok || invite.consumed || !invite.expires.After(time.Now()) {
		return auth.ErrInviteInvalid
	}
	return nil
}

func (d *memoryDirectory) AcceptInvite(_ context.Context, token string, identity auth.Identity) (auth.Admin, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	invite, ok := d.invites[auth.HashToken(token)]
	if !ok || invite.consumed || !invite.expires.After(time.Now()) {
		return auth.Admin{}, auth.ErrInviteInvalid
	}
	matched := false
	for _, email := range identity.Emails {
		if email == invite.email {
			matched = true
			break
		}
	}
	if invite.email != "" && !matched {
		return auth.Admin{}, auth.ErrEmailMismatch
	}
	for _, admin := range d.admins {
		if admin.Provider == identity.Provider && admin.Subject == identity.Subject {
			return admin, nil
		}
	}
	invite.consumed = true
	d.invites[auth.HashToken(token)] = invite
	admin := auth.Admin{
		ID:       "admin-created",
		Provider: identity.Provider,
		Subject:  identity.Subject,
		Login:    identity.Login,
		Name:     identity.Name,
	}
	d.admins = append(d.admins, admin)
	return admin, nil
}

func cookieNamed(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func stateFromRedirect(t *testing.T, location string) string {
	t.Helper()
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("redirect %s has no state", location)
	}
	return state
}

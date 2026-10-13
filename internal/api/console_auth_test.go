package api

import (
	"context"
	"encoding/json"
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
	token := directory.addInvite("")
	provider := fakeProvider{identity: auth.Identity{Provider: auth.ProviderGitHub, Subject: "7", Login: "ada", Name: "Ada"}}
	server := NewServer(nil, "secret").WithConsoleAuth(ConsoleAuth{
		Directory: directory,
		PublicURL: "http://localhost:8080",
		Providers: map[string]auth.Provider{auth.ProviderGitHub: provider},
	})
	handler := server.Handler()

	start := httptest.NewRequest(http.MethodGet, "/auth/github/start?invite="+token, nil)
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

	keyOnly := httptest.NewRequest(http.MethodPost, "/v1/admins/invites", nil)
	keyOnly.Header.Set("X-API-Key", "secret")
	keyRec := httptest.NewRecorder()
	handler.ServeHTTP(keyRec, keyOnly)
	if keyRec.Code != http.StatusUnauthorized {
		t.Fatalf("api key invite status = %d", keyRec.Code)
	}

	invite := httptest.NewRequest(http.MethodPost, "/v1/admins/invites", nil)
	invite.AddCookie(session)
	inviteRec := httptest.NewRecorder()
	handler.ServeHTTP(inviteRec, invite)
	if inviteRec.Code != http.StatusCreated {
		t.Fatalf("invite status = %d body %s", inviteRec.Code, inviteRec.Body.String())
	}
	var created struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(inviteRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.URL, "http://localhost:8080/setup/") {
		t.Fatalf("invite url = %s", created.URL)
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
	handler := NewServer(nil, "secret").WithConsoleAuth(ConsoleAuth{
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
	handler := (&Server{apiSecret: "secret"}).Handler()
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
	mu       sync.Mutex
	admins   []auth.Admin
	invites  map[string]memoryInvite
	sessions map[string]string
}

type memoryInvite struct {
	expires  time.Time
	consumed bool
}

func newMemoryDirectory() *memoryDirectory {
	return &memoryDirectory{
		invites:  map[string]memoryInvite{},
		sessions: map[string]string{},
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

func (d *memoryDirectory) CreateInvite(context.Context, string) (string, time.Time, error) {
	token := d.addInvite("admin")
	return token, time.Now().Add(time.Hour), nil
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

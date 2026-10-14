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
	var sentTo, sentPassword string
	provider := fakeProvider{identity: auth.Identity{Provider: auth.ProviderGitHub, Subject: "7", Login: "ada", Name: "Ada", Emails: []string{"ada@example.com"}}}
	server := NewServer(nil).WithConsoleAuth(ConsoleAuth{
		Directory: directory,
		PublicURL: "http://localhost:8080",
		Providers: map[string]auth.Provider{auth.ProviderGitHub: provider},
		SendPassword: func(_ context.Context, to, password string) error {
			sentTo, sentPassword = to, password
			return nil
		},
	})
	handler := server.Handler()

	setup := httptest.NewRequest(http.MethodPost, "/v1/auth/setup", strings.NewReader(`{"email":"ada@example.com","password":"correct-horse-battery"}`))
	setupRec := httptest.NewRecorder()
	handler.ServeHTTP(setupRec, setup)
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup status = %d body %s", setupRec.Code, setupRec.Body.String())
	}
	session := cookieNamed(setupRec.Result().Cookies(), sessionCookie)
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

	keyOnly := httptest.NewRequest(http.MethodPost, "/v1/admins", strings.NewReader(`{"email":"next@example.com"}`))
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

	invite := httptest.NewRequest(http.MethodPost, "/v1/admins", strings.NewReader(`{"email":"next@example.com"}`))
	invite.Header.Set("Content-Type", "application/json")
	invite.AddCookie(session)
	inviteRec := httptest.NewRecorder()
	handler.ServeHTTP(inviteRec, invite)
	if inviteRec.Code != http.StatusCreated || !strings.Contains(inviteRec.Body.String(), `"password"`) {
		t.Fatalf("create admin status = %d body %s", inviteRec.Code, inviteRec.Body.String())
	}
	if sentTo != "next@example.com" || sentPassword == "" {
		t.Fatalf("sent %s %s", sentTo, sentPassword)
	}

	list := httptest.NewRequest(http.MethodGet, "/v1/admins", nil)
	list.AddCookie(session)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, list)
	if listRec.Code != http.StatusOK || !strings.Contains(listRec.Body.String(), `"login":"ada@example.com"`) {
		t.Fatalf("list = %d %s", listRec.Code, listRec.Body.String())
	}

	remove := httptest.NewRequest(http.MethodDelete, "/v1/admins/"+url.PathEscape("admin-next@example.com"), nil)
	remove.AddCookie(session)
	removeRec := httptest.NewRecorder()
	handler.ServeHTTP(removeRec, remove)
	if removeRec.Code != http.StatusNoContent {
		t.Fatalf("delete one of two = %d", removeRec.Code)
	}
	last := httptest.NewRequest(http.MethodDelete, "/v1/admins/"+directory.onlyID(), nil)
	last.AddCookie(session)
	lastRec := httptest.NewRecorder()
	handler.ServeHTTP(lastRec, last)
	if lastRec.Code != http.StatusConflict {
		t.Fatalf("delete last = %d", lastRec.Code)
	}
}

func TestConsoleLoginRejectsUnknownAccount(t *testing.T) {
	directory := newMemoryDirectory()
	directory.seed(auth.Admin{ID: "admin-1", Provider: auth.ProviderPassword, Subject: "known@example.com", Login: "known@example.com", Email: "known@example.com"})
	provider := fakeProvider{identity: auth.Identity{Provider: auth.ProviderGitHub, Subject: "9", Login: "stranger", Emails: []string{"stranger@example.com"}}}
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

func TestForgotPasswordResetsTheAccount(t *testing.T) {
	directory := newMemoryDirectory()
	var resetTo, resetURL string
	var sent int
	handler := NewServer(nil).WithConsoleAuth(ConsoleAuth{
		Directory: directory,
		PublicURL: "https://om.example",
		SendReset: func(_ context.Context, to, link string) error {
			sent++
			resetTo, resetURL = to, link
			return nil
		},
	}).Handler()

	setup := httptest.NewRequest(http.MethodPost, "/v1/auth/setup", strings.NewReader(`{"email":"ada@example.com","password":"correct-horse-battery"}`))
	setupRec := httptest.NewRecorder()
	handler.ServeHTTP(setupRec, setup)
	if setupRec.Code != http.StatusOK {
		t.Fatalf("setup = %d %s", setupRec.Code, setupRec.Body.String())
	}
	session := cookieNamed(setupRec.Result().Cookies(), sessionCookie)

	probe := httptest.NewRecorder()
	handler.ServeHTTP(probe, httptest.NewRequest(http.MethodGet, "/v1/auth/session", nil))
	if !strings.Contains(probe.Body.String(), `"password_reset":true`) {
		t.Fatalf("session = %s", probe.Body.String())
	}

	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodPost, "/v1/auth/forgot", strings.NewReader(`{"email":"missing@example.com"}`)))
	if missing.Code != http.StatusOK || sent != 0 {
		t.Fatalf("unknown email = %d sent %d", missing.Code, sent)
	}

	forgot := httptest.NewRecorder()
	handler.ServeHTTP(forgot, httptest.NewRequest(http.MethodPost, "/v1/auth/forgot", strings.NewReader(`{"email":"Ada@Example.com"}`)))
	if forgot.Code != http.StatusOK || sent != 1 || resetTo != "ada@example.com" {
		t.Fatalf("forgot = %d sent %d to %s", forgot.Code, sent, resetTo)
	}
	parsed, err := url.Parse(resetURL)
	if err != nil {
		t.Fatal(err)
	}
	token := parsed.Query().Get("reset")
	if token == "" || !strings.HasPrefix(resetURL, "https://om.example/login?reset=") {
		t.Fatalf("reset url = %s", resetURL)
	}

	short := httptest.NewRecorder()
	handler.ServeHTTP(short, httptest.NewRequest(http.MethodPost, "/v1/auth/reset", strings.NewReader(`{"token":"`+token+`","password":"short"}`)))
	if short.Code != http.StatusBadRequest {
		t.Fatalf("short password = %d %s", short.Code, short.Body.String())
	}

	reset := httptest.NewRecorder()
	handler.ServeHTTP(reset, httptest.NewRequest(http.MethodPost, "/v1/auth/reset", strings.NewReader(`{"token":"`+token+`","password":"a-new-password-ok"}`)))
	if reset.Code != http.StatusNoContent {
		t.Fatalf("reset = %d %s", reset.Code, reset.Body.String())
	}

	oldSession := httptest.NewRecorder()
	rules := httptest.NewRequest(http.MethodGet, "/v1/rules", nil)
	rules.AddCookie(session)
	handler.ServeHTTP(oldSession, rules)
	if oldSession.Code != http.StatusUnauthorized {
		t.Fatalf("old session = %d", oldSession.Code)
	}

	reuse := httptest.NewRecorder()
	handler.ServeHTTP(reuse, httptest.NewRequest(http.MethodPost, "/v1/auth/reset", strings.NewReader(`{"token":"`+token+`","password":"another-password-ok"}`)))
	if reuse.Code != http.StatusBadRequest {
		t.Fatalf("reuse = %d %s", reuse.Code, reuse.Body.String())
	}

	oldLogin := httptest.NewRecorder()
	handler.ServeHTTP(oldLogin, httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"ada@example.com","password":"correct-horse-battery"}`)))
	if oldLogin.Code != http.StatusUnauthorized {
		t.Fatalf("old password = %d", oldLogin.Code)
	}
	newLogin := httptest.NewRecorder()
	handler.ServeHTTP(newLogin, httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"ada@example.com","password":"a-new-password-ok"}`)))
	if newLogin.Code != http.StatusOK {
		t.Fatalf("new password = %d %s", newLogin.Code, newLogin.Body.String())
	}
}

func TestForgotPasswordRequiresMail(t *testing.T) {
	handler := NewServer(nil).WithConsoleAuth(ConsoleAuth{Directory: newMemoryDirectory()}).Handler()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/auth/forgot", strings.NewReader(`{"email":"ada@example.com"}`)))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d %s", recorder.Code, recorder.Body.String())
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
	passwords  map[string]string
	challenges map[string]string
	resets     map[string]memoryReset
	plainToken string
}

type memoryReset struct {
	adminID string
	expires time.Time
}

type memoryInvite struct {
	expires  time.Time
	consumed bool
	email    string
}

func newMemoryDirectory() *memoryDirectory {
	return &memoryDirectory{
		invites:    map[string]memoryInvite{},
		sessions:   map[string]string{},
		tokens:     map[string]string{},
		previews:   map[string]string{},
		passwords:  map[string]string{},
		challenges: map[string]string{},
		resets:     map[string]memoryReset{},
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

func (d *memoryDirectory) FindByEmail(_ context.Context, email string) (auth.Admin, bool, error) {
	email, err := auth.NormalizeEmail(email)
	if err != nil {
		return auth.Admin{}, false, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, admin := range d.admins {
		if strings.EqualFold(admin.Email, email) {
			return admin, true, nil
		}
	}
	return auth.Admin{}, false, nil
}

func (d *memoryDirectory) SetupAdmin(_ context.Context, email, password, pinned string) (auth.Admin, error) {
	email, err := auth.NormalizeEmail(email)
	if err != nil {
		return auth.Admin{}, err
	}
	if pinned != "" {
		pinned, err = auth.NormalizeEmail(pinned)
		if err != nil {
			return auth.Admin{}, err
		}
		if email != pinned {
			return auth.Admin{}, auth.ErrSetupEmail
		}
	}
	if err := auth.ValidatePassword(password); err != nil {
		return auth.Admin{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.admins) > 0 {
		return auth.Admin{}, auth.ErrAdminsExist
	}
	admin := auth.Admin{ID: "admin-created", Provider: auth.ProviderPassword, Subject: email, Login: email, Email: email}
	d.admins = append(d.admins, admin)
	d.passwords[email] = password
	d.plainToken = "personal-token"
	d.tokens[auth.HashToken(d.plainToken)] = admin.ID
	d.previews[admin.ID] = d.plainToken
	return admin, nil
}

func (d *memoryDirectory) CreateWithPassword(ctx context.Context, email, password string, mustChange bool) (auth.Admin, error) {
	email, err := auth.NormalizeEmail(email)
	if err != nil {
		return auth.Admin{}, err
	}
	if err := auth.ValidatePassword(password); err != nil {
		return auth.Admin{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, admin := range d.admins {
		if strings.EqualFold(admin.Email, email) {
			return auth.Admin{}, auth.ErrEmailTaken
		}
	}
	admin := auth.Admin{ID: "admin-" + email, Provider: auth.ProviderPassword, Subject: email, Login: email, Email: email, MustChangePassword: mustChange}
	d.admins = append(d.admins, admin)
	d.passwords[email] = password
	return admin, nil
}

func (d *memoryDirectory) ProvisionAdmin(ctx context.Context, email string) (auth.Admin, string, error) {
	password := "temporary-password-value"
	admin, err := d.CreateWithPassword(ctx, email, password, true)
	return admin, password, err
}

func (d *memoryDirectory) CheckPassword(_ context.Context, email, password string) (auth.Admin, error) {
	email, err := auth.NormalizeEmail(email)
	if err != nil {
		return auth.Admin{}, auth.ErrBadCredentials
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.passwords[email] != password {
		return auth.Admin{}, auth.ErrBadCredentials
	}
	for _, admin := range d.admins {
		if strings.EqualFold(admin.Email, email) {
			return admin, nil
		}
	}
	return auth.Admin{}, auth.ErrBadCredentials
}

func (d *memoryDirectory) ChangePassword(_ context.Context, adminID, current, next string) error {
	if err := auth.ValidatePassword(next); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, admin := range d.admins {
		if admin.ID != adminID {
			continue
		}
		if d.passwords[admin.Email] != current {
			return auth.ErrBadCredentials
		}
		d.passwords[admin.Email] = next
		d.admins[i].MustChangePassword = false
		return nil
	}
	return auth.ErrNotFound
}

func (d *memoryDirectory) RequestPasswordReset(_ context.Context, email string) (string, error) {
	email, err := auth.NormalizeEmail(email)
	if err != nil {
		return "", nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var admin auth.Admin
	found := false
	for _, candidate := range d.admins {
		if candidate.Provider == auth.ProviderPassword && strings.EqualFold(candidate.Email, email) && d.passwords[email] != "" {
			admin = candidate
			found = true
			break
		}
	}
	if !found {
		return "", nil
	}
	for hash, reset := range d.resets {
		if reset.adminID == admin.ID {
			delete(d.resets, hash)
		}
	}
	token := "reset-" + admin.ID
	d.resets[auth.HashToken(token)] = memoryReset{adminID: admin.ID, expires: time.Now().Add(time.Hour)}
	return token, nil
}

func (d *memoryDirectory) CompletePasswordReset(_ context.Context, token, password string) error {
	if err := auth.ValidatePassword(password); err != nil {
		return err
	}
	if token == "" || len(token) > 128 {
		return auth.ErrResetInvalid
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	key := auth.HashToken(token)
	reset, ok := d.resets[key]
	if !ok || !reset.expires.After(time.Now()) {
		delete(d.resets, key)
		return auth.ErrResetInvalid
	}
	delete(d.resets, key)
	for i, admin := range d.admins {
		if admin.ID != reset.adminID {
			continue
		}
		d.passwords[admin.Email] = password
		d.admins[i].MustChangePassword = false
		for hash, id := range d.sessions {
			if id == admin.ID {
				delete(d.sessions, hash)
			}
		}
		return nil
	}
	return auth.ErrResetInvalid
}

func (d *memoryDirectory) SetPassword(ctx context.Context, email, password string) error {
	admin, found, err := d.FindByEmail(ctx, email)
	if err != nil || !found {
		return auth.ErrNotFound
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.passwords[admin.Email] = password
	return nil
}

func (d *memoryDirectory) BeginTOTP(context.Context, string) (string, error) {
	return "SECRET", nil
}

func (d *memoryDirectory) ConfirmTOTP(context.Context, string, string) ([]string, error) {
	return []string{"code"}, nil
}

func (d *memoryDirectory) DisableTOTP(context.Context, string, string, string) error {
	return nil
}

func (d *memoryDirectory) VerifySecondFactor(context.Context, string, string) error {
	return nil
}

func (d *memoryDirectory) CreateLoginChallenge(_ context.Context, adminID string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.challenges[auth.HashToken("challenge")] = adminID
	return "challenge", nil
}

func (d *memoryDirectory) ConsumeLoginChallenge(_ context.Context, token string) (auth.Admin, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	id, ok := d.challenges[auth.HashToken(token)]
	if !ok {
		return auth.Admin{}, auth.ErrNotFound
	}
	delete(d.challenges, auth.HashToken(token))
	for _, admin := range d.admins {
		if admin.ID == id {
			return admin, nil
		}
	}
	return auth.Admin{}, auth.ErrNotFound
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

package controller

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
)

func TestOIDCIdentityAllowed(t *testing.T) {
	claims := oidcClaims{Subject: "subject-1", Email: "Admin@Example.test"}
	if !oidcIdentityAllowed(claims, config.AuthConfig{}) {
		t.Fatal("an empty allowlist should permit a provider-authenticated identity")
	}
	if !oidcIdentityAllowed(claims, config.AuthConfig{OIDCAllowedEmails: []string{"admin@example.test"}}) {
		t.Fatal("email allowlist matching should be case-insensitive")
	}
	if oidcIdentityAllowed(claims, config.AuthConfig{OIDCAllowedEmails: []string{"other@example.test"}}) {
		t.Fatal("identity outside the configured allowlist was permitted")
	}
}

func TestOIDCIdentityLabel(t *testing.T) {
	claims := oidcClaims{Subject: "subject-1", Name: "Panel Admin", PreferredUsername: "admin", Email: "admin@example.test"}
	if got := oidcIdentityLabel(claims); got != "admin@example.test" {
		t.Fatalf("identity label = %q", got)
	}
	claims.Email = ""
	if got := oidcIdentityLabel(claims); got != "admin" {
		t.Fatalf("identity label fallback = %q", got)
	}
}

func TestPasswordLoginDisabledAtEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"admin","password":"secret"}`))
	c.Request.Header.Set("Content-Type", "application/json")

	controller := IndexController{authConfig: config.AuthConfig{PasswordLoginEnabled: false}}
	controller.login(c)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if !strings.Contains(recorder.Body.String(), "Password login is disabled") {
		t.Fatalf("response = %s", recorder.Body.String())
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !constantTimeEqual("same", "same") {
		t.Fatal("equal values did not match")
	}
	if constantTimeEqual("same", "different") || constantTimeEqual("same", "samf") {
		t.Fatal("different values matched")
	}
}

func TestOIDCLoginUsesStateNonceAndPKCE(t *testing.T) {
	var issuer string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	issuer = provider.URL
	defer provider.Close()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(sessions.Sessions("3x-ui", cookie.NewStore([]byte("01234567890123456789012345678901"))))
	router.Use(func(c *gin.Context) {
		c.Set("base_path", "/")
		c.Next()
	})
	controller := &IndexController{authConfig: config.AuthConfig{
		OIDCEnabled:          true,
		PasswordLoginEnabled: false,
		OIDCIssuerURL:        issuer,
		OIDCClientID:         "panel-client",
		OIDCClientSecret:     "secret",
		OIDCRedirectURL:      "https://panel.example.test/oidc/callback",
		OIDCScopes:           []string{"openid", "profile", "email"},
	}}
	router.GET("/oidc/login", controller.oidcLogin)
	router.GET("/oidc/callback", controller.oidcCallback)
	app := httptest.NewServer(router)
	defer app.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(app.URL + "/oidc/login")
	if err != nil {
		t.Fatalf("start OIDC login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse authorization redirect: %v", err)
	}
	query := location.Query()
	for _, name := range []string{"state", "nonce", "code_challenge"} {
		if query.Get(name) == "" {
			t.Errorf("authorization redirect has no %s", name)
		}
	}
	if query.Get("code_challenge_method") != "S256" {
		t.Errorf("PKCE method = %q", query.Get("code_challenge_method"))
	}
	if query.Get("client_id") != "panel-client" {
		t.Errorf("client_id = %q", query.Get("client_id"))
	}
	if query.Get("redirect_uri") != "https://panel.example.test/oidc/callback" {
		t.Errorf("redirect_uri = %q", query.Get("redirect_uri"))
	}

	callbackResp, err := client.Get(app.URL + "/oidc/callback?code=unused&state=wrong")
	if err != nil {
		t.Fatalf("call OIDC callback: %v", err)
	}
	defer callbackResp.Body.Close()
	if callbackResp.StatusCode != http.StatusSeeOther || callbackResp.Header.Get("Location") != "/?oidc_error=1" {
		t.Fatalf("invalid state response = %d location %q", callbackResp.StatusCode, callbackResp.Header.Get("Location"))
	}
}

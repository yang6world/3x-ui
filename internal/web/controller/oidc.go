package controller

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service/tgbot"
	panelsession "github.com/mhsanaei/3x-ui/v3/internal/web/session"
)

const (
	oidcStateKey       = "OIDC_STATE"
	oidcNonceKey       = "OIDC_NONCE"
	oidcPKCEKey        = "OIDC_PKCE"
	oidcStartedAtKey   = "OIDC_STARTED_AT"
	oidcFlowMaxAge     = 10 * time.Minute
	oidcRequestTimeout = 15 * time.Second
)

type oidcProviderCache struct {
	mu       sync.Mutex
	issuer   string
	provider *oidc.Provider
}

func (p *oidcProviderCache) get(ctx context.Context, issuer string) (*oidc.Provider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.provider != nil && p.issuer == issuer {
		return p.provider, nil
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	p.issuer = issuer
	p.provider = provider
	return provider, nil
}

type oidcClaims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
}

func (a *IndexController) oidcLogin(c *gin.Context) {
	if !a.authConfig.OIDCEnabled {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	state, err := randomURLSafe(32)
	if err != nil {
		a.oidcFail(c, fmt.Errorf("generate state: %w", err))
		return
	}
	nonce, err := randomURLSafe(32)
	if err != nil {
		a.oidcFail(c, fmt.Errorf("generate nonce: %w", err))
		return
	}
	verifier := oauth2.GenerateVerifier()

	s := sessions.Default(c)
	s.Set(oidcStateKey, state)
	s.Set(oidcNonceKey, nonce)
	s.Set(oidcPKCEKey, verifier)
	s.Set(oidcStartedAtKey, time.Now().Unix())
	if err := s.Save(); err != nil {
		a.oidcFail(c, fmt.Errorf("save authorization state: %w", err))
		return
	}

	ctx, cancel := oidcHTTPContext(c.Request.Context())
	defer cancel()
	provider, err := a.oidcProviders.get(ctx, a.authConfig.OIDCIssuerURL)
	if err != nil {
		a.oidcFail(c, fmt.Errorf("discover provider: %w", err))
		return
	}
	oauthConfig := a.oauth2Config(provider)
	authorizationURL := oauthConfig.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusSeeOther, authorizationURL)
}

func (a *IndexController) oidcCallback(c *gin.Context) {
	if !a.authConfig.OIDCEnabled {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	s := sessions.Default(c)
	wantState, stateOK := s.Get(oidcStateKey).(string)
	wantNonce, nonceOK := s.Get(oidcNonceKey).(string)
	verifier, verifierOK := s.Get(oidcPKCEKey).(string)
	startedAt, startedOK := sessionUnix(s.Get(oidcStartedAtKey))
	flowAge := time.Since(time.Unix(startedAt, 0))
	clearOIDCFlow(s)
	if err := s.Save(); err != nil {
		a.oidcFail(c, fmt.Errorf("consume authorization state: %w", err))
		return
	}

	if providerError := strings.TrimSpace(c.Query("error")); providerError != "" {
		a.oidcFail(c, fmt.Errorf("provider rejected authorization: %s", providerError))
		return
	}
	if !stateOK || !nonceOK || !verifierOK || !startedOK ||
		flowAge < 0 || flowAge > oidcFlowMaxAge ||
		!constantTimeEqual(wantState, c.Query("state")) {
		a.oidcFail(c, errors.New("invalid or expired authorization state"))
		return
	}
	code := strings.TrimSpace(c.Query("code"))
	if code == "" {
		a.oidcFail(c, errors.New("authorization code is missing"))
		return
	}

	ctx, cancel := oidcHTTPContext(c.Request.Context())
	defer cancel()
	provider, err := a.oidcProviders.get(ctx, a.authConfig.OIDCIssuerURL)
	if err != nil {
		a.oidcFail(c, fmt.Errorf("discover provider: %w", err))
		return
	}
	oauthConfig := a.oauth2Config(provider)
	token, err := oauthConfig.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		a.oidcFail(c, fmt.Errorf("exchange authorization code: %w", err))
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		a.oidcFail(c, errors.New("provider response did not include an ID token"))
		return
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: a.authConfig.OIDCClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		a.oidcFail(c, fmt.Errorf("verify ID token: %w", err))
		return
	}
	if !constantTimeEqual(wantNonce, idToken.Nonce) {
		a.oidcFail(c, errors.New("ID token nonce does not match"))
		return
	}
	var claims oidcClaims
	if err := idToken.Claims(&claims); err != nil {
		a.oidcFail(c, fmt.Errorf("decode ID token claims: %w", err))
		return
	}
	if strings.TrimSpace(claims.Subject) == "" {
		a.oidcFail(c, errors.New("ID token subject is missing"))
		return
	}
	if !oidcIdentityAllowed(claims, a.authConfig) {
		a.oidcFail(c, errors.New("OIDC identity is not authorized"))
		return
	}

	user, err := a.userService.GetFirstUser()
	if err != nil {
		a.oidcFail(c, fmt.Errorf("load panel administrator: %w", err))
		return
	}
	if err := panelsession.SetLoginUser(c, user); err != nil {
		a.oidcFail(c, fmt.Errorf("save login session: %w", err))
		return
	}

	identity := oidcIdentityLabel(claims)
	remoteIP := getRemoteIp(c)
	logger.Infof("OIDC identity %q logged in successfully, Ip Address: %s", identity, remoteIP)
	a.tgbot.UserLoginNotify(tgbot.LoginAttempt{
		Username: identity,
		IP:       remoteIP,
		Time:     time.Now().Format("2006-01-02 15:04:05"),
		Status:   tgbot.LoginSuccess,
	})
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusSeeOther, c.GetString("base_path")+"panel/")
}

func (a *IndexController) oauth2Config(provider *oidc.Provider) oauth2.Config {
	return oauth2.Config{
		ClientID:     a.authConfig.OIDCClientID,
		ClientSecret: a.authConfig.OIDCClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  a.authConfig.OIDCRedirectURL,
		Scopes:       a.authConfig.OIDCScopes,
	}
}

func (a *IndexController) oidcFail(c *gin.Context, err error) {
	logger.Warningf("OIDC login failed: %v", err)
	c.Header("Cache-Control", "no-store")
	basePath := c.GetString("base_path")
	if basePath == "" {
		basePath = "/"
	}
	c.Redirect(http.StatusSeeOther, basePath+"?oidc_error=1")
}

func oidcHTTPContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(parent, oidcRequestTimeout)
	client := &http.Client{Timeout: oidcRequestTimeout}
	return oidc.ClientContext(ctx, client), cancel
}

func randomURLSafe(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func constantTimeEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func clearOIDCFlow(s sessions.Session) {
	s.Delete(oidcStateKey)
	s.Delete(oidcNonceKey)
	s.Delete(oidcPKCEKey)
	s.Delete(oidcStartedAtKey)
}

func sessionUnix(value any) (int64, bool) {
	switch v := value.(type) {
	case int64:
		return v, v > 0
	case int:
		return int64(v), v > 0
	case float64:
		return int64(v), v > 0 && v == float64(int64(v))
	default:
		return 0, false
	}
}

func oidcIdentityAllowed(claims oidcClaims, cfg config.AuthConfig) bool {
	if len(cfg.OIDCAllowedEmails) == 0 {
		return true
	}
	email := strings.TrimSpace(claims.Email)
	for _, allowed := range cfg.OIDCAllowedEmails {
		if strings.EqualFold(email, strings.TrimSpace(allowed)) {
			return true
		}
	}
	return false
}

func oidcIdentityLabel(claims oidcClaims) string {
	for _, value := range []string{claims.Email, claims.PreferredUsername, claims.Name, claims.Subject} {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return "unknown"
}

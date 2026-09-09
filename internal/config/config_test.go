package config

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"testing"
)

func TestGetPanelVersion(t *testing.T) {
	orig := buildCommit
	t.Cleanup(func() { buildCommit = orig })

	buildCommit = ""
	if got := GetPanelVersion(); got != GetBaseVersion() {
		t.Fatalf("stable build: GetPanelVersion = %q, want %q", got, GetBaseVersion())
	}

	buildCommit = "1d1128cf"
	if got := GetPanelVersion(); got != "dev+1d1128cf" {
		t.Fatalf("dev build: GetPanelVersion = %q, want %q", got, "dev+1d1128cf")
	}

	buildCommit = "1d1128cf945c4615efa05cf41ba7fa766e2ee428"
	if got := GetPanelVersion(); got != "dev+1d1128cf" {
		t.Fatalf("dev build (full sha): GetPanelVersion = %q, want %q", got, "dev+1d1128cf")
	}
}

func TestGetPortOverride(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		set        bool
		wantPort   int
		configured bool
		wantErr    bool
	}{
		{name: "unset"},
		{name: "empty", value: "", set: true},
		{name: "whitespace", value: "   ", set: true},
		{name: "minimum", value: "1", set: true, wantPort: 1, configured: true},
		{name: "default panel port", value: "2053", set: true, wantPort: 2053, configured: true},
		{name: "surrounding whitespace", value: " 8080 ", set: true, wantPort: 8080, configured: true},
		{name: "maximum", value: "65535", set: true, wantPort: 65535, configured: true},
		{name: "zero", value: "0", set: true, configured: true, wantErr: true},
		{name: "above maximum", value: "65536", set: true, configured: true, wantErr: true},
		{name: "negative", value: "-1", set: true, configured: true, wantErr: true},
		{name: "non-numeric", value: "abc", set: true, configured: true, wantErr: true},
		{name: "decimal", value: "8080.0", set: true, configured: true, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.set {
				t.Setenv("XUI_PORT", tt.value)
			} else {
				original, existed := os.LookupEnv("XUI_PORT")
				if err := os.Unsetenv("XUI_PORT"); err != nil {
					t.Fatalf("unset XUI_PORT: %v", err)
				}
				t.Cleanup(func() {
					if existed {
						_ = os.Setenv("XUI_PORT", original)
					} else {
						_ = os.Unsetenv("XUI_PORT")
					}
				})
			}

			port, configured, err := GetPortOverride()
			if port != tt.wantPort {
				t.Errorf("port = %d, want %d", port, tt.wantPort)
			}
			if configured != tt.configured {
				t.Errorf("configured = %t, want %t", configured, tt.configured)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestGetAuthConfigDefaults(t *testing.T) {
	clearAuthEnv(t)
	cfg, err := GetAuthConfig()
	if err != nil {
		t.Fatalf("GetAuthConfig: %v", err)
	}
	if cfg.OIDCEnabled {
		t.Fatal("OIDC must be disabled by default")
	}
	if !cfg.PasswordLoginEnabled {
		t.Fatal("password login must remain enabled by default")
	}
	if cfg.OIDCProviderName != "OpenID Connect" {
		t.Fatalf("provider name = %q", cfg.OIDCProviderName)
	}
}

func TestGetAuthConfigOIDC(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("XUI_OIDC_ENABLED", "true")
	t.Setenv("XUI_PASSWORD_LOGIN_ENABLED", "false")
	t.Setenv("XUI_OIDC_ISSUER_URL", "https://id.example.test/realms/panel")
	t.Setenv("XUI_OIDC_CLIENT_ID", "panel")
	t.Setenv("XUI_OIDC_CLIENT_SECRET", "must-not-leak")
	t.Setenv("XUI_OIDC_REDIRECT_URL", "https://panel.example.test/secret/oidc/callback")
	t.Setenv("XUI_OIDC_PROVIDER_NAME", "Example SSO")
	t.Setenv("XUI_OIDC_SCOPES", "profile,email,profile")
	t.Setenv("XUI_OIDC_ALLOWED_EMAILS", "Admin@example.test, other@example.test")

	cfg, err := GetAuthConfig()
	if err != nil {
		t.Fatalf("GetAuthConfig: %v", err)
	}
	if !cfg.OIDCEnabled || cfg.PasswordLoginEnabled {
		t.Fatalf("unexpected auth modes: %#v", cfg.Public())
	}
	if !slices.Equal(cfg.OIDCScopes, []string{"openid", "profile", "email"}) {
		t.Fatalf("scopes = %#v", cfg.OIDCScopes)
	}
	if !slices.Equal(cfg.OIDCAllowedEmails, []string{"Admin@example.test", "other@example.test"}) {
		t.Fatalf("allowed emails = %#v", cfg.OIDCAllowedEmails)
	}
	publicJSON, err := json.Marshal(cfg.Public())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(publicJSON, []byte("must-not-leak")) {
		t.Fatal("public auth config contains the OIDC client secret")
	}
}

func TestGetAuthConfigRejectsUnsafeOrIncompleteModes(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{name: "invalid OIDC boolean", env: map[string]string{"XUI_OIDC_ENABLED": "sometimes"}},
		{name: "no login method", env: map[string]string{"XUI_PASSWORD_LOGIN_ENABLED": "false"}},
		{name: "missing issuer", env: map[string]string{"XUI_OIDC_ENABLED": "true"}},
		{name: "missing client id", env: map[string]string{"XUI_OIDC_ENABLED": "true", "XUI_OIDC_ISSUER_URL": "https://id.example.test"}},
		{name: "missing redirect URL", env: map[string]string{"XUI_OIDC_ENABLED": "true", "XUI_OIDC_ISSUER_URL": "https://id.example.test", "XUI_OIDC_CLIENT_ID": "panel"}},
		{name: "relative redirect URL", env: map[string]string{"XUI_OIDC_ENABLED": "true", "XUI_OIDC_ISSUER_URL": "https://id.example.test", "XUI_OIDC_CLIENT_ID": "panel", "XUI_OIDC_REDIRECT_URL": "/oidc/callback"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearAuthEnv(t)
			for name, value := range tt.env {
				t.Setenv(name, value)
			}
			if _, err := GetAuthConfig(); err == nil {
				t.Fatal("GetAuthConfig succeeded, want validation error")
			}
		})
	}
}

func clearAuthEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"XUI_OIDC_ENABLED",
		"XUI_PASSWORD_LOGIN_ENABLED",
		"XUI_OIDC_ISSUER_URL",
		"XUI_OIDC_CLIENT_ID",
		"XUI_OIDC_CLIENT_SECRET",
		"XUI_OIDC_REDIRECT_URL",
		"XUI_OIDC_PROVIDER_NAME",
		"XUI_OIDC_SCOPES",
		"XUI_OIDC_ALLOWED_EMAILS",
	} {
		t.Setenv(name, "")
	}
}

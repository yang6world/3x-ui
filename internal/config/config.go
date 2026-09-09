// Package config provides configuration management utilities for the 3x-ui panel,
// including version information, logging levels, database paths, and environment variable handling.
package config

import (
	_ "embed"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

//go:embed version
var version string

//go:embed name
var name string

// buildCommit and buildDate are injected at build time via `-ldflags -X` for
// CI per-commit (dev channel) builds; see .github/workflows/release.yml. They
// stay empty for a plain `go build` and for stable tagged releases, which is how
// IsDevBuild tells a rolling dev build apart from a stable/local one.
var (
	buildCommit string
	buildDate   string
)

// LogLevel represents the logging level for the application.
type LogLevel string

// Logging level constants
const (
	Debug   LogLevel = "debug"
	Info    LogLevel = "info"
	Notice  LogLevel = "notice"
	Warning LogLevel = "warning"
	Error   LogLevel = "error"
)

// GetBaseVersion returns the raw embedded release version of the 3x-ui panel
// (e.g. "3.4.0"). This is the panel's own version, not the Xray version. For the
// version a panel advertises/displays (which adds a "dev+<sha>" label on dev
// builds), use GetPanelVersion.
func GetBaseVersion() string {
	return strings.TrimSpace(version)
}

// GetName returns the name of the 3x-ui application.
func GetName() string {
	return strings.TrimSpace(name)
}

// GetBuildCommit returns the short git commit this binary was built from, or an
// empty string for a plain/local build or a stable tagged release.
func GetBuildCommit() string {
	return strings.TrimSpace(buildCommit)
}

// GetBuildDate returns the UTC build timestamp injected at build time, or empty.
func GetBuildDate() string {
	return strings.TrimSpace(buildDate)
}

// IsDevBuild reports whether this binary is a CI per-commit (dev channel) build,
// detected by the injected commit. Stable releases and local builds return false.
func IsDevBuild() bool {
	return GetBuildCommit() != ""
}

// GetPanelVersion returns the version a panel advertises to a managing master
// node and displays in the UI: the plain version for stable builds, or
// "dev+<short commit>" for dev builds. The dev form mirrors the master's
// getPanelUpdateInfo latestVersion so a node on the current dev commit compares
// as up to date instead of always showing "update available".
func GetPanelVersion() string {
	if !IsDevBuild() {
		return GetBaseVersion()
	}
	commit := GetBuildCommit()
	if len(commit) > 8 {
		commit = commit[:8]
	}
	return "dev+" + commit
}

// GetLogLevel returns the current logging level based on environment variables or defaults to Info.
func GetLogLevel() LogLevel {
	if IsDebug() {
		return Debug
	}
	logLevel := os.Getenv("XUI_LOG_LEVEL")
	if logLevel == "" {
		return Info
	}
	return LogLevel(logLevel)
}

// IsDebug returns true if debug mode is enabled via the XUI_DEBUG environment variable.
func IsDebug() bool {
	return os.Getenv("XUI_DEBUG") == "true"
}

// IsSkipHSTS returns true if skipping HSTS mode is enabled via the XUI_SKIP_HSTS environment variable.
func IsSkipHSTS() bool {
	return os.Getenv("XUI_SKIP_HSTS") == "true"
}

// AuthConfig contains the environment-backed authentication settings. Secrets
// in this struct must never be serialized into a response or injected into a
// page; use PublicAuthConfig for browser-facing configuration.
type AuthConfig struct {
	OIDCEnabled          bool
	PasswordLoginEnabled bool
	OIDCIssuerURL        string
	OIDCClientID         string
	OIDCClientSecret     string
	OIDCRedirectURL      string
	OIDCProviderName     string
	OIDCScopes           []string
	OIDCAllowedEmails    []string
}

// PublicAuthConfig is the non-sensitive subset exposed to the login page.
type PublicAuthConfig struct {
	OIDCEnabled          bool   `json:"oidcEnabled"`
	PasswordLoginEnabled bool   `json:"passwordLoginEnabled"`
	OIDCProviderName     string `json:"oidcProviderName"`
}

// GetAuthConfig parses and validates the panel authentication environment.
// Password login remains enabled by default for backwards compatibility.
func GetAuthConfig() (AuthConfig, error) {
	oidcEnabled, err := envBool("XUI_OIDC_ENABLED", false)
	if err != nil {
		return AuthConfig{}, err
	}
	passwordEnabled, err := envBool("XUI_PASSWORD_LOGIN_ENABLED", true)
	if err != nil {
		return AuthConfig{}, err
	}

	cfg := AuthConfig{
		OIDCEnabled:          oidcEnabled,
		PasswordLoginEnabled: passwordEnabled,
		OIDCIssuerURL:        strings.TrimSpace(os.Getenv("XUI_OIDC_ISSUER_URL")),
		OIDCClientID:         strings.TrimSpace(os.Getenv("XUI_OIDC_CLIENT_ID")),
		OIDCClientSecret:     os.Getenv("XUI_OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:      strings.TrimSpace(os.Getenv("XUI_OIDC_REDIRECT_URL")),
		OIDCProviderName:     strings.TrimSpace(os.Getenv("XUI_OIDC_PROVIDER_NAME")),
		OIDCScopes:           splitEnvList(os.Getenv("XUI_OIDC_SCOPES")),
		OIDCAllowedEmails:    splitEnvList(os.Getenv("XUI_OIDC_ALLOWED_EMAILS")),
	}
	if cfg.OIDCProviderName == "" {
		cfg.OIDCProviderName = "OpenID Connect"
	}
	if len(cfg.OIDCScopes) == 0 {
		cfg.OIDCScopes = []string{"openid", "profile", "email"}
	} else if !containsFold(cfg.OIDCScopes, "openid") {
		cfg.OIDCScopes = append([]string{"openid"}, cfg.OIDCScopes...)
	}

	if !cfg.OIDCEnabled {
		if !cfg.PasswordLoginEnabled {
			return AuthConfig{}, fmt.Errorf("XUI_PASSWORD_LOGIN_ENABLED=false requires XUI_OIDC_ENABLED=true")
		}
		return cfg, nil
	}
	if cfg.OIDCIssuerURL == "" {
		return AuthConfig{}, fmt.Errorf("XUI_OIDC_ISSUER_URL is required when OIDC is enabled")
	}
	if cfg.OIDCClientID == "" {
		return AuthConfig{}, fmt.Errorf("XUI_OIDC_CLIENT_ID is required when OIDC is enabled")
	}
	if cfg.OIDCRedirectURL == "" {
		return AuthConfig{}, fmt.Errorf("XUI_OIDC_REDIRECT_URL is required when OIDC is enabled")
	}
	redirectURL, err := url.Parse(cfg.OIDCRedirectURL)
	if err != nil || !redirectURL.IsAbs() || (redirectURL.Scheme != "http" && redirectURL.Scheme != "https") || redirectURL.Host == "" {
		return AuthConfig{}, fmt.Errorf("XUI_OIDC_REDIRECT_URL must be an absolute http or https URL")
	}
	issuerURL, err := url.Parse(cfg.OIDCIssuerURL)
	if err != nil || !issuerURL.IsAbs() || (issuerURL.Scheme != "http" && issuerURL.Scheme != "https") || issuerURL.Host == "" {
		return AuthConfig{}, fmt.Errorf("XUI_OIDC_ISSUER_URL must be an absolute http or https URL")
	}

	return cfg, nil
}

func (c AuthConfig) Public() PublicAuthConfig {
	return PublicAuthConfig{
		OIDCEnabled:          c.OIDCEnabled,
		PasswordLoginEnabled: c.PasswordLoginEnabled,
		OIDCProviderName:     c.OIDCProviderName,
	}
}

func envBool(name string, fallback bool) (bool, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	value, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", name, err)
	}
	return value, nil
}

func splitEnvList(raw string) []string {
	seen := make(map[string]struct{})
	var values []string
	for value := range strings.FieldsFuncSeq(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		value = strings.TrimSpace(value)
		key := strings.ToLower(value)
		if value == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		values = append(values, value)
	}
	return values
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

func GetPortOverride() (port int, configured bool, err error) {
	value, ok := os.LookupEnv("XUI_PORT")
	if !ok || strings.TrimSpace(value) == "" {
		return 0, false, nil
	}

	port, err = strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, true, fmt.Errorf("parse XUI_PORT: %w", err)
	}
	if port < 1 || port > 65535 {
		return 0, true, fmt.Errorf("XUI_PORT must be between 1 and 65535")
	}

	return port, true, nil
}

// GetBinFolderPath returns the path to the binary folder, defaulting to "bin" if not set via XUI_BIN_FOLDER.
func GetBinFolderPath() string {
	binFolderPath := os.Getenv("XUI_BIN_FOLDER")
	if binFolderPath == "" {
		binFolderPath = "bin"
	}
	return binFolderPath
}

func getBaseDir() string {
	exePath, err := os.Executable()
	if err != nil {
		return "."
	}
	exeDir := filepath.Dir(exePath)
	exeDirLower := strings.ToLower(filepath.ToSlash(exeDir))
	if strings.Contains(exeDirLower, "/appdata/local/temp/") || strings.Contains(exeDirLower, "/go-build") {
		wd, err := os.Getwd()
		if err != nil {
			return "."
		}
		return wd
	}
	return exeDir
}

// GetDBFolderPath returns the path to the database folder based on environment variables or platform defaults.
func GetDBFolderPath() string {
	dbFolderPath := os.Getenv("XUI_DB_FOLDER")
	if dbFolderPath != "" {
		return dbFolderPath
	}
	if runtime.GOOS == "windows" {
		return getBaseDir()
	}
	return "/etc/x-ui"
}

// GetDBPath returns the full path to the database file.
func GetDBPath() string {
	return fmt.Sprintf("%s/%s.db", GetDBFolderPath(), GetName())
}

// GetUpdateStatusFilePath returns the path to the panel self-update status
// file update.sh writes on completion. It lives beside the database, outside
// XUI_MAIN_FOLDER, so it survives an update regardless of what happens to
// that folder.
func GetUpdateStatusFilePath() string {
	return filepath.Join(GetDBFolderPath(), "update-status.json")
}

// GetDBKind returns the configured database backend: "sqlite" (default) or "postgres".
func GetDBKind() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("XUI_DB_TYPE")))
	switch v {
	case "postgres", "postgresql", "pg":
		return "postgres"
	default:
		return "sqlite"
	}
}

// GetDBDSN returns the PostgreSQL DSN from XUI_DB_DSN. Empty for sqlite.
func GetDBDSN() string {
	return strings.TrimSpace(os.Getenv("XUI_DB_DSN"))
}

// GetNodeTokenEncryptionMode returns off, migration, or required. Explicit
// policy prevents a missing key from silently downgrading encrypted storage.
func GetNodeTokenEncryptionMode() string {
	return strings.TrimSpace(os.Getenv("NODE_TOKEN_ENCRYPTION"))
}

// GetNodeTokenKeyFile returns the mode-0600 keyring path, configurable through
// XUI_NODE_TOKEN_KEY_FILE.
func GetNodeTokenKeyFile() string {
	if p := strings.TrimSpace(os.Getenv("XUI_NODE_TOKEN_KEY_FILE")); p != "" {
		return p
	}
	return "/etc/x-ui/node_token_key.json"
}

// GetNodeTokenKeyEnv returns the name of the env var holding a single base64
// 32-byte node-token key (secondary to the key file). Empty value => unused.
func GetNodeTokenKeyEnv() string {
	return "XUI_NODE_TOKEN_KEY"
}

// GetEnvFilePaths returns the candidate service environment file paths (the file
// systemd loads via EnvironmentFile) across the supported distro families.
func GetEnvFilePaths() []string {
	if runtime.GOOS == "windows" {
		return nil
	}
	return []string{
		"/etc/default/x-ui",
		"/etc/conf.d/x-ui",
		"/etc/sysconfig/x-ui",
	}
}

// GetLogFolder returns the path to the log folder based on environment variables or platform defaults.
func GetLogFolder() string {
	logFolderPath := os.Getenv("XUI_LOG_FOLDER")
	if logFolderPath != "" {
		return logFolderPath
	}
	// Under `go test` the Windows default below is CWD-relative ("./log"), which
	// scatters a log/ directory through the source tree (one per tested package).
	// Redirect test runs to a shared temp folder so the source tree stays clean.
	if testing.Testing() {
		return filepath.Join(os.TempDir(), "3x-ui-test-log")
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(".", "log")
	}
	return "/var/log/x-ui"
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}

	return out.Sync()
}

func init() {
	if runtime.GOOS != "windows" {
		return
	}
	if os.Getenv("XUI_DB_FOLDER") != "" {
		return
	}
	oldDBFolder := "/etc/x-ui"
	oldDBPath := fmt.Sprintf("%s/%s.db", oldDBFolder, GetName())
	newDBFolder := GetDBFolderPath()
	newDBPath := fmt.Sprintf("%s/%s.db", newDBFolder, GetName())
	_, err := os.Stat(newDBPath)
	if err == nil {
		return // new exists
	}
	_, err = os.Stat(oldDBPath)
	if os.IsNotExist(err) {
		return // old does not exist
	}
	_ = copyFile(oldDBPath, newDBPath) // ignore error
}

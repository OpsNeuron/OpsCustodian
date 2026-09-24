package controlplane

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const controlPlaneTestAPIToken = "opscustodian-control-plane-test-token-0123456789abcdef"

func TestConfigFromEnvironmentUsesBoundedOperationalDefaults(t *testing.T) {
	config, err := ConfigFromEnvironment(environment(map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID": "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":    "postgres://custodian:secret@database/controlplane?sslmode=verify-full",
		"OPSCUSTODIAN_API_TOKEN":       controlPlaneTestAPIToken,
		"OPSCUSTODIAN_API_TOKEN_ID":    "platform-reader",
		"OPSCUSTODIAN_API_SCOPES":      "control-plane:read",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if config.OrganizationDisplayName != config.OrganizationID || !config.ApplyMigrations {
		t.Fatalf("unexpected identity defaults: %#v", config.Safe())
	}
	if config.ConnectTimeout != 5*time.Second || config.MigrationTimeout != 2*time.Minute || config.ShutdownTimeout != 10*time.Second {
		t.Fatalf("unexpected timeout defaults: %#v", config.Safe())
	}
	if config.MaxOpenConns != 20 || config.MaxIdleConns != 5 || config.ConnMaxLifetime != 30*time.Minute {
		t.Fatalf("unexpected pool defaults: %#v", config.Safe())
	}
	if config.SchedulerLeaseTTL != time.Minute || config.SchedulerRenewInterval != 20*time.Second {
		t.Fatalf("unexpected scheduler defaults: %#v", config.Safe())
	}
}

func TestConfigFromEnvironmentAcceptsExplicitPoolAndLifecycleSettings(t *testing.T) {
	config, err := ConfigFromEnvironment(environment(map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID":            "organization-0123456789abcdef",
		"OPSCUSTODIAN_ORGANIZATION_DISPLAY_NAME":  "Agent Platform",
		"OPSCUSTODIAN_DATABASE_DSN":               "postgres://database/controlplane",
		"OPSCUSTODIAN_DATABASE_ALLOW_INSECURE":    "true",
		"OPSCUSTODIAN_API_TOKEN":                  controlPlaneTestAPIToken,
		"OPSCUSTODIAN_API_TOKEN_ID":               "platform-reader",
		"OPSCUSTODIAN_API_SCOPES":                 "control-plane:read",
		"OPSCUSTODIAN_DATABASE_MIGRATE":           "false",
		"OPSCUSTODIAN_DATABASE_CONNECT_TIMEOUT":   "15s",
		"OPSCUSTODIAN_DATABASE_MIGRATION_TIMEOUT": "3m",
		"OPSCUSTODIAN_SHUTDOWN_TIMEOUT":           "25s",
		"OPSCUSTODIAN_DATABASE_MAX_OPEN_CONNS":    "40",
		"OPSCUSTODIAN_DATABASE_MAX_IDLE_CONNS":    "10",
		"OPSCUSTODIAN_DATABASE_CONN_MAX_LIFETIME": "2h",
		"OPSCUSTODIAN_SCHEDULER_LEASE_TTL":        "90s",
		"OPSCUSTODIAN_SCHEDULER_RENEW_INTERVAL":   "30s",
		"OPSCUSTODIAN_HTTP_LISTEN_ADDRESS":        "[::1]:9090",
		"OPSCUSTODIAN_HTTP_READ_HEADER_TIMEOUT":   "4s",
		"OPSCUSTODIAN_HTTP_READ_TIMEOUT":          "12s",
		"OPSCUSTODIAN_HTTP_WRITE_TIMEOUT":         "20s",
		"OPSCUSTODIAN_HTTP_IDLE_TIMEOUT":          "45s",
		"OPSCUSTODIAN_HTTP_MAX_HEADER_BYTES":      "32768",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if config.ApplyMigrations || config.MigrationTimeout != 3*time.Minute || config.MaxOpenConns != 40 || config.MaxIdleConns != 10 || config.ConnMaxLifetime != 2*time.Hour {
		t.Fatalf("explicit settings were not preserved: %#v", config.Safe())
	}
	if config.HTTP.ListenAddress != "[::1]:9090" || config.HTTP.ReadTimeout != 12*time.Second || config.HTTP.MaxHeaderBytes != 32768 {
		t.Fatalf("explicit HTTP settings were not preserved: %#v", config.Safe())
	}
	if config.SchedulerLeaseTTL != 90*time.Second || config.SchedulerRenewInterval != 30*time.Second {
		t.Fatalf("explicit scheduler settings were not preserved: %#v", config.Safe())
	}
}

func TestConfigRejectsInvalidOrUnsafeOperationalBounds(t *testing.T) {
	tests := []struct {
		name, variable, value, message string
	}{
		{"missing tenant", "OPSCUSTODIAN_ORGANIZATION_ID", "", "ORGANIZATION_ID"},
		{"invalid migration", "OPSCUSTODIAN_DATABASE_MIGRATE", "sometimes", "true or false"},
		{"unbounded connect", "OPSCUSTODIAN_DATABASE_CONNECT_TIMEOUT", "2m", "between"},
		{"unbounded migration", "OPSCUSTODIAN_DATABASE_MIGRATION_TIMEOUT", "16m", "between"},
		{"unbounded pool", "OPSCUSTODIAN_DATABASE_MAX_OPEN_CONNS", "1001", "between"},
		{"idle exceeds open", "OPSCUSTODIAN_DATABASE_MAX_IDLE_CONNS", "21", "max open"},
		{"short scheduler lease", "OPSCUSTODIAN_SCHEDULER_LEASE_TTL", "10s", "between"},
		{"slow scheduler renewal", "OPSCUSTODIAN_SCHEDULER_RENEW_INTERVAL", "1m", "less than"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := map[string]string{
				"OPSCUSTODIAN_ORGANIZATION_ID":         "organization-0123456789abcdef",
				"OPSCUSTODIAN_DATABASE_DSN":            "postgres://database/controlplane",
				"OPSCUSTODIAN_DATABASE_ALLOW_INSECURE": "true",
				"OPSCUSTODIAN_API_TOKEN":               controlPlaneTestAPIToken,
				"OPSCUSTODIAN_API_TOKEN_ID":            "platform-reader",
				"OPSCUSTODIAN_API_SCOPES":              "control-plane:read",
			}
			values[test.variable] = test.value
			_, err := ConfigFromEnvironment(environment(values))
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("error = %v, expected %q", err, test.message)
			}
		})
	}
}

func TestSafeConfigNeverContainsDatabaseCredentials(t *testing.T) {
	secret := "credential-that-must-not-escape"
	config, err := ConfigFromEnvironment(environment(map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID":         "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":            "postgres://custodian:" + secret + "@database/controlplane",
		"OPSCUSTODIAN_DATABASE_ALLOW_INSECURE": "true",
		"OPSCUSTODIAN_API_TOKEN":               controlPlaneTestAPIToken,
		"OPSCUSTODIAN_API_TOKEN_ID":            "platform-reader",
		"OPSCUSTODIAN_API_SCOPES":              "control-plane:read",
	}))
	if err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(config.Safe())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), secret) || strings.Contains(string(content), controlPlaneTestAPIToken) || strings.Contains(string(content), "postgres://") {
		t.Fatalf("safe configuration leaked a secret: %s", content)
	}
	if !strings.Contains(string(content), `"authenticationConfigured":true`) {
		t.Fatalf("safe configuration omitted authentication state: %s", content)
	}
}

func TestConfigRequiresStrongAPIToken(t *testing.T) {
	values := map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID":         "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":            "postgres://database/controlplane",
		"OPSCUSTODIAN_DATABASE_ALLOW_INSECURE": "true",
		"OPSCUSTODIAN_API_SCOPES":              "control-plane:read",
		"OPSCUSTODIAN_API_TOKEN_ID":            "platform-reader",
	}
	if _, err := ConfigFromEnvironment(environment(values)); err == nil || !strings.Contains(err.Error(), "OPSCUSTODIAN_API_TOKEN") {
		t.Fatalf("missing token error = %v", err)
	}
	values["OPSCUSTODIAN_API_TOKEN"] = "short"
	if _, err := ConfigFromEnvironment(environment(values)); err == nil || !strings.Contains(err.Error(), "OPSCUSTODIAN_API_TOKEN") {
		t.Fatalf("weak token error = %v", err)
	}
}

func TestConfigRequiresSupportedAuthorizationScope(t *testing.T) {
	values := map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID":         "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":            "postgres://database/controlplane",
		"OPSCUSTODIAN_DATABASE_ALLOW_INSECURE": "true",
		"OPSCUSTODIAN_API_TOKEN":               controlPlaneTestAPIToken,
		"OPSCUSTODIAN_API_TOKEN_ID":            "platform-reader",
	}
	if _, err := ConfigFromEnvironment(environment(values)); err == nil || !strings.Contains(err.Error(), "OPSCUSTODIAN_API_SCOPES") {
		t.Fatalf("missing scope error = %v", err)
	}
	values["OPSCUSTODIAN_API_SCOPES"] = "admin"
	if _, err := ConfigFromEnvironment(environment(values)); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported scope error = %v", err)
	}
}

func TestConfigRequiresValidCredentialID(t *testing.T) {
	values := map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID":         "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":            "postgres://database/controlplane",
		"OPSCUSTODIAN_DATABASE_ALLOW_INSECURE": "true",
		"OPSCUSTODIAN_API_TOKEN":               controlPlaneTestAPIToken,
		"OPSCUSTODIAN_API_SCOPES":              "control-plane:read",
	}
	for _, identity := range []string{"", "Admin", "1reader", "reader_one"} {
		values["OPSCUSTODIAN_API_TOKEN_ID"] = identity
		if _, err := ConfigFromEnvironment(environment(values)); err == nil || !strings.Contains(err.Error(), "OPSCUSTODIAN_API_TOKEN_ID") {
			t.Fatalf("credential ID %q error = %v", identity, err)
		}
	}
}

func TestConfigAcceptsMultiCredentialRegistryWithoutLeakingTokens(t *testing.T) {
	first := "inventory-registry-token-0123456789abcdef"
	second := "findings-registry-token-0123456789abcdef0"
	config, err := ConfigFromEnvironment(environment(map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID":         "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":            "postgres://database/controlplane",
		"OPSCUSTODIAN_DATABASE_ALLOW_INSECURE": "true",
		"OPSCUSTODIAN_API_CREDENTIALS":         `[{"id":"inventory-reader","token":"` + first + `","scopes":["inventory:read"]},{"id":"findings-reader","token":"` + second + `","scopes":["findings:read"]}]`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(config.Safe())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), first) || strings.Contains(string(content), second) || !strings.Contains(string(content), "inventory-reader") || !strings.Contains(string(content), "findings-reader") {
		t.Fatalf("unsafe multi-credential projection: %s", content)
	}
}

func TestConfigEnablesSecretSafeRepositoryAuthorization(t *testing.T) {
	repositoryID := "repository-0123456789abcdef"
	config, err := ConfigFromEnvironment(environment(map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID":         "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":            "postgres://database/controlplane",
		"OPSCUSTODIAN_DATABASE_ALLOW_INSECURE": "true",
		"OPSCUSTODIAN_API_TOKEN":               controlPlaneTestAPIToken,
		"OPSCUSTODIAN_API_TOKEN_ID":            "repository-reader",
		"OPSCUSTODIAN_API_SCOPES":              "inventory:read",
		"OPSCUSTODIAN_API_REPOSITORIES":        repositoryID,
	}))
	if err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(config.Safe())
	if err != nil {
		t.Fatal(err)
	}
	if !config.RepositoryAuthorization || !strings.Contains(string(content), `"repositoryAuthorizationConfigured":true`) || strings.Contains(string(content), repositoryID) {
		t.Fatalf("unsafe repository authorization projection: %s", content)
	}
}

func TestConfigRejectsMixedCredentialModes(t *testing.T) {
	_, err := ConfigFromEnvironment(environment(map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID":         "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":            "postgres://database/controlplane",
		"OPSCUSTODIAN_DATABASE_ALLOW_INSECURE": "true",
		"OPSCUSTODIAN_API_CREDENTIALS":         `[{"id":"reader","token":"registry-token-0123456789abcdefghijkl","scopes":["inventory:read"]}]`,
		"OPSCUSTODIAN_API_TOKEN":               controlPlaneTestAPIToken,
	}))
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("mixed credential error = %v", err)
	}
}

func TestConfigRejectsRepositoryAuthorizationMixedWithRegistryMode(t *testing.T) {
	_, err := ConfigFromEnvironment(environment(map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID":         "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":            "postgres://database/controlplane",
		"OPSCUSTODIAN_DATABASE_ALLOW_INSECURE": "true",
		"OPSCUSTODIAN_API_CREDENTIALS":         `[{"id":"reader","token":"registry-token-0123456789abcdefghijkl","scopes":["inventory:read"]}]`,
		"OPSCUSTODIAN_API_REPOSITORIES":        "repository-0123456789abcdef",
	}))
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("mixed repository authorization error = %v", err)
	}
}

func TestConfigAcceptsCredentialLifecycleFields(t *testing.T) {
	_, err := ConfigFromEnvironment(environment(map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID":         "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":            "postgres://database/controlplane",
		"OPSCUSTODIAN_DATABASE_ALLOW_INSECURE": "true",
		"OPSCUSTODIAN_API_CREDENTIALS":         `[{"id":"old-reader","token":"old-config-token-0123456789abcdefghijkl","scopes":["inventory:read"],"expiresAt":"2026-08-21T00:00:00Z"},{"id":"new-reader","token":"new-config-token-0123456789abcdefghijkl","scopes":["inventory:read"],"notBefore":"2026-08-20T00:00:00Z"},{"id":"disabled-reader","token":"disabled-config-token-0123456789abcdefgh","scopes":["inventory:read"],"disabled":true}]`,
	}))
	if err != nil {
		t.Fatal(err)
	}
}

func TestConfigEnablesSecretSafeCredentialFileReload(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "credentials.json")
	config, err := ConfigFromEnvironment(environment(map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID":                "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":                   "postgres://database/controlplane",
		"OPSCUSTODIAN_DATABASE_ALLOW_INSECURE":        "true",
		"OPSCUSTODIAN_API_TOKEN":                      controlPlaneTestAPIToken,
		"OPSCUSTODIAN_API_TOKEN_ID":                   "bootstrap-reader",
		"OPSCUSTODIAN_API_SCOPES":                     "control-plane:read",
		"OPSCUSTODIAN_API_CREDENTIAL_FILE":            secretPath,
		"OPSCUSTODIAN_API_CREDENTIAL_RELOAD_INTERVAL": "15s",
	}))
	if err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(config.Safe())
	if err != nil {
		t.Fatal(err)
	}
	if config.CredentialReloadInterval != 15*time.Second || !strings.Contains(string(content), `"credentialFileConfigured":true`) || strings.Contains(string(content), secretPath) {
		t.Fatalf("safe credential file config = %s", content)
	}
}

func TestConfigRejectsUnsafeCredentialFileSettings(t *testing.T) {
	base := map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID":         "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":            "postgres://database/controlplane",
		"OPSCUSTODIAN_DATABASE_ALLOW_INSECURE": "true",
		"OPSCUSTODIAN_API_TOKEN":               controlPlaneTestAPIToken,
		"OPSCUSTODIAN_API_TOKEN_ID":            "bootstrap-reader",
		"OPSCUSTODIAN_API_SCOPES":              "control-plane:read",
	}
	base["OPSCUSTODIAN_API_CREDENTIAL_FILE"] = "relative/credentials.json"
	if _, err := ConfigFromEnvironment(environment(base)); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative path error = %v", err)
	}
	delete(base, "OPSCUSTODIAN_API_CREDENTIAL_FILE")
	base["OPSCUSTODIAN_API_CREDENTIAL_RELOAD_INTERVAL"] = "15s"
	if _, err := ConfigFromEnvironment(environment(base)); err == nil || !strings.Contains(err.Error(), "requires") {
		t.Fatalf("orphan interval error = %v", err)
	}
}

func TestConfigEnablesSecretSafeRepositorySet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repositories.json")
	values := map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID": "organization-0123456789abcdef", "OPSCUSTODIAN_DATABASE_DSN": "postgres://database/controlplane",
		"OPSCUSTODIAN_DATABASE_ALLOW_INSECURE": "true", "OPSCUSTODIAN_API_TOKEN": controlPlaneTestAPIToken,
		"OPSCUSTODIAN_API_TOKEN_ID": "bootstrap-reader", "OPSCUSTODIAN_API_SCOPES": "control-plane:read",
		"OPSCUSTODIAN_REPOSITORY_SET_FILE": path,
	}
	config, err := ConfigFromEnvironment(environment(values))
	if err != nil {
		t.Fatal(err)
	}
	content, _ := json.Marshal(config.Safe())
	if config.RepositorySetFile != path || !strings.Contains(string(content), `"repositorySetConfigured":true`) || strings.Contains(string(content), path) {
		t.Fatalf("safe repository set config = %s", content)
	}
	values["OPSCUSTODIAN_REPOSITORY_SET_FILE"] = "relative/repositories.json"
	if _, err := ConfigFromEnvironment(environment(values)); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative repository set error = %v", err)
	}
}

func TestConfigEnablesSecretSafeGitHubAppAuthentication(t *testing.T) {
	privateKeyPath := filepath.Join(t.TempDir(), "github-app.pem")
	values := map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID": "organization-0123456789abcdef", "OPSCUSTODIAN_DATABASE_DSN": "postgres://database/controlplane",
		"OPSCUSTODIAN_DATABASE_ALLOW_INSECURE": "true", "OPSCUSTODIAN_API_TOKEN": controlPlaneTestAPIToken,
		"OPSCUSTODIAN_API_TOKEN_ID": "bootstrap-reader", "OPSCUSTODIAN_API_SCOPES": "control-plane:read",
		"OPSCUSTODIAN_GITHUB_APP_ID": "1234", "OPSCUSTODIAN_GITHUB_APP_PRIVATE_KEY_FILE": privateKeyPath,
	}
	config, err := ConfigFromEnvironment(environment(values))
	if err != nil {
		t.Fatal(err)
	}
	content, _ := json.Marshal(config.Safe())
	if config.GitHubAppID != 1234 || config.GitHubAppPrivateKeyFile != privateKeyPath || !strings.Contains(string(content), `"githubAppConfigured":true`) || strings.Contains(string(content), privateKeyPath) {
		t.Fatalf("safe GitHub App config = %s", content)
	}
	delete(values, "OPSCUSTODIAN_GITHUB_APP_PRIVATE_KEY_FILE")
	if _, err := ConfigFromEnvironment(environment(values)); err == nil || !strings.Contains(err.Error(), "configured together") {
		t.Fatalf("incomplete GitHub App error = %v", err)
	}
	values["OPSCUSTODIAN_GITHUB_APP_PRIVATE_KEY_FILE"] = "relative/app.pem"
	if _, err := ConfigFromEnvironment(environment(values)); err == nil || !strings.Contains(err.Error(), "clean absolute") {
		t.Fatalf("relative key error = %v", err)
	}
}

func TestConfigEnablesSecretSafePolicyRuntime(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policies")
	config, err := ConfigFromEnvironment(environment(map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID":         "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":            "postgres://database/controlplane",
		"OPSCUSTODIAN_DATABASE_ALLOW_INSECURE": "true",
		"OPSCUSTODIAN_API_TOKEN":               controlPlaneTestAPIToken,
		"OPSCUSTODIAN_API_TOKEN_ID":            "policy-client",
		"OPSCUSTODIAN_API_SCOPES":              "policy:evaluate",
		"OPSCUSTODIAN_POLICY_PATH":             policyPath,
		"OPSCUSTODIAN_OPA_BINARY":              "opa-custom",
		"OPSCUSTODIAN_POLICY_QUERY":            "data.example.decision",
		"OPSCUSTODIAN_POLICY_TIMEOUT":          "7s",
	}))
	if err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(config.Safe())
	if err != nil {
		t.Fatal(err)
	}
	if config.PolicyPath != policyPath || config.PolicyBinary != "opa-custom" || config.PolicyQuery != "data.example.decision" || config.PolicyTimeout != 7*time.Second {
		t.Fatalf("policy configuration was not preserved: %#v", config)
	}
	if strings.Contains(string(content), policyPath) || strings.Contains(string(content), "opa-custom") || !strings.Contains(string(content), `"policyConfigured":true`) {
		t.Fatalf("unsafe policy projection: %s", content)
	}
}

func TestConfigRejectsUnsafePolicyRuntimeSettings(t *testing.T) {
	base := map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID":         "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":            "postgres://database/controlplane",
		"OPSCUSTODIAN_DATABASE_ALLOW_INSECURE": "true",
		"OPSCUSTODIAN_API_TOKEN":               controlPlaneTestAPIToken,
		"OPSCUSTODIAN_API_TOKEN_ID":            "policy-client",
		"OPSCUSTODIAN_API_SCOPES":              "policy:evaluate",
	}
	base["OPSCUSTODIAN_POLICY_PATH"] = "relative/policies"
	if _, err := ConfigFromEnvironment(environment(base)); err == nil || !strings.Contains(err.Error(), "clean absolute") {
		t.Fatalf("relative policy path error = %v", err)
	}
	delete(base, "OPSCUSTODIAN_POLICY_PATH")
	base["OPSCUSTODIAN_POLICY_TIMEOUT"] = "5s"
	if _, err := ConfigFromEnvironment(environment(base)); err == nil || !strings.Contains(err.Error(), "require OPSCUSTODIAN_POLICY_PATH") {
		t.Fatalf("orphan policy setting error = %v", err)
	}
	base["OPSCUSTODIAN_POLICY_PATH"] = filepath.Join(t.TempDir(), "policies")
	base["OPSCUSTODIAN_POLICY_TIMEOUT"] = "31s"
	if _, err := ConfigFromEnvironment(environment(base)); err == nil || !strings.Contains(err.Error(), "between") {
		t.Fatalf("unbounded policy timeout error = %v", err)
	}
}

func environment(values map[string]string) LookupEnv {
	return func(name string) (string, bool) {
		value, exists := values[name]
		return value, exists
	}
}

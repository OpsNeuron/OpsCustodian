package controlplane

import (
	"encoding/json"
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

func environment(values map[string]string) LookupEnv {
	return func(name string) (string, bool) {
		value, exists := values[name]
		return value, exists
	}
}

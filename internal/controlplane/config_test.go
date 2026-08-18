package controlplane

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestConfigFromEnvironmentUsesBoundedOperationalDefaults(t *testing.T) {
	config, err := ConfigFromEnvironment(environment(map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID": "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":    "postgres://custodian:secret@database/controlplane?sslmode=verify-full",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if config.OrganizationDisplayName != config.OrganizationID || !config.ApplyMigrations {
		t.Fatalf("unexpected identity defaults: %#v", config.Safe())
	}
	if config.ConnectTimeout != 5*time.Second || config.ShutdownTimeout != 10*time.Second {
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
		"OPSCUSTODIAN_DATABASE_MIGRATE":           "false",
		"OPSCUSTODIAN_DATABASE_CONNECT_TIMEOUT":   "15s",
		"OPSCUSTODIAN_SHUTDOWN_TIMEOUT":           "25s",
		"OPSCUSTODIAN_DATABASE_MAX_OPEN_CONNS":    "40",
		"OPSCUSTODIAN_DATABASE_MAX_IDLE_CONNS":    "10",
		"OPSCUSTODIAN_DATABASE_CONN_MAX_LIFETIME": "2h",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if config.ApplyMigrations || config.MaxOpenConns != 40 || config.MaxIdleConns != 10 || config.ConnMaxLifetime != 2*time.Hour {
		t.Fatalf("explicit settings were not preserved: %#v", config.Safe())
	}
}

func TestConfigRejectsInvalidOrUnsafeOperationalBounds(t *testing.T) {
	tests := []struct {
		name, variable, value, message string
	}{
		{"missing tenant", "OPSCUSTODIAN_ORGANIZATION_ID", "", "ORGANIZATION_ID"},
		{"invalid migration", "OPSCUSTODIAN_DATABASE_MIGRATE", "sometimes", "true or false"},
		{"unbounded connect", "OPSCUSTODIAN_DATABASE_CONNECT_TIMEOUT", "2m", "between"},
		{"unbounded pool", "OPSCUSTODIAN_DATABASE_MAX_OPEN_CONNS", "1001", "between"},
		{"idle exceeds open", "OPSCUSTODIAN_DATABASE_MAX_IDLE_CONNS", "21", "max open"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := map[string]string{
				"OPSCUSTODIAN_ORGANIZATION_ID": "organization-0123456789abcdef",
				"OPSCUSTODIAN_DATABASE_DSN":    "postgres://database/controlplane",
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
		"OPSCUSTODIAN_ORGANIZATION_ID": "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":    "postgres://custodian:" + secret + "@database/controlplane",
	}))
	if err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(config.Safe())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), secret) || strings.Contains(string(content), "postgres://") {
		t.Fatalf("safe configuration leaked database DSN: %s", content)
	}
}

func environment(values map[string]string) LookupEnv {
	return func(name string) (string, bool) {
		value, exists := values[name]
		return value, exists
	}
}

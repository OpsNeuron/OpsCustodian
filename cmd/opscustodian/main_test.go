package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/opscustodian/opscustodian/internal/contracts"
	"github.com/opscustodian/opscustodian/internal/controlplane"
)

func TestWriteVersionSupportsTerminalAndMachineReadableContracts(t *testing.T) {
	var terminal bytes.Buffer
	if err := writeVersion(&terminal, "v0.4.0-test", "terminal"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(terminal.String(), "opscustodian v0.4.0-test") || !strings.Contains(terminal.String(), contracts.AgentBOMAPIVersion) {
		t.Fatalf("terminal version output is incomplete: %s", terminal.String())
	}

	var output bytes.Buffer
	if err := writeVersion(&output, "v0.4.0-test", "json"); err != nil {
		t.Fatal(err)
	}
	var info contracts.Info
	if err := json.Unmarshal(output.Bytes(), &info); err != nil {
		t.Fatalf("invalid version JSON: %v", err)
	}
	if info.Version != "v0.4.0-test" || info.Contracts.PolicyInput != contracts.PolicyInputAPIVersion {
		t.Fatalf("unexpected version JSON: %#v", info)
	}
	if err := writeVersion(&bytes.Buffer{}, "dev", "yaml"); err == nil || !strings.Contains(err.Error(), "unsupported version format") {
		t.Fatalf("unsupported format error = %v", err)
	}
}

func TestServeCommandPrintsOnlySafeValidatedConfiguration(t *testing.T) {
	secret, token := "database-password-secret", "opscustodian-cli-test-token-0123456789abcdef"
	var output bytes.Buffer
	called := false
	err := serveCommand(context.Background(), []string{"--print-config"}, cliEnvironment(map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID": "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":    "postgres://custodian:" + secret + "@database.example/opscustodian?sslmode=verify-full",
		"OPSCUSTODIAN_API_TOKEN":       token,
		"OPSCUSTODIAN_API_SCOPES":      "control-plane:read",
	}), &output, func() (controlplane.ProcessDependencies, error) {
		called = true
		return controlplane.ProcessDependencies{}, nil
	}, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	if called || strings.Contains(output.String(), secret) || strings.Contains(output.String(), token) || !strings.Contains(output.String(), `"authenticationConfigured": true`) {
		t.Fatalf("safe config output = %s, factory called = %v", output.String(), called)
	}
}

func TestServeCommandInvokesProcessWithValidatedConfiguration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	factoryCalled, runnerCalled := false, false
	err := serveCommand(ctx, nil, cliEnvironment(map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID":         "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":            "postgres://database/opscustodian?sslmode=disable",
		"OPSCUSTODIAN_DATABASE_ALLOW_INSECURE": "true",
		"OPSCUSTODIAN_API_TOKEN":               "opscustodian-cli-test-token-0123456789abcdef",
		"OPSCUSTODIAN_API_SCOPES":              "control-plane:read",
	}), &bytes.Buffer{}, func() (controlplane.ProcessDependencies, error) {
		factoryCalled = true
		return controlplane.ProcessDependencies{}, nil
	}, func(received context.Context, config controlplane.Config, buildVersion string, _ controlplane.ProcessDependencies) error {
		runnerCalled = true
		if !errors.Is(received.Err(), context.Canceled) || config.OrganizationID != "organization-0123456789abcdef" || buildVersion != "v0.5.0-test" {
			t.Fatalf("runner inputs = %v, %#v, %q", received.Err(), config.Safe(), buildVersion)
		}
		return nil
	}, "v0.5.0-test")
	if err != nil || !factoryCalled || !runnerCalled {
		t.Fatalf("serve result = %v, factory = %v, runner = %v", err, factoryCalled, runnerCalled)
	}
}

func TestServeCommandRejectsInvalidConfigurationBeforeProcessInitialization(t *testing.T) {
	factoryCalled := false
	err := serveCommand(context.Background(), nil, cliEnvironment(map[string]string{
		"OPSCUSTODIAN_ORGANIZATION_ID": "organization-0123456789abcdef",
		"OPSCUSTODIAN_DATABASE_DSN":    "postgres://database/opscustodian?sslmode=verify-full",
	}), &bytes.Buffer{}, func() (controlplane.ProcessDependencies, error) {
		factoryCalled = true
		return controlplane.ProcessDependencies{}, nil
	}, nil, "test")
	if err == nil || !strings.Contains(err.Error(), "OPSCUSTODIAN_API_TOKEN") || factoryCalled {
		t.Fatalf("invalid config error = %v, factory called = %v", err, factoryCalled)
	}
}

func cliEnvironment(values map[string]string) controlplane.LookupEnv {
	return func(name string) (string, bool) {
		value, exists := values[name]
		return value, exists
	}
}

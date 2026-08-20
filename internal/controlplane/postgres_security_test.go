package controlplane

import (
	"strings"
	"testing"
)

func TestDatabaseTransportRequiresVerifiedTLS(t *testing.T) {
	secure := []string{
		"postgres://custodian@database.example/opscustodian?sslmode=verify-full",
		"host=database.example dbname=opscustodian user=custodian sslmode=verify-full",
		"postgres://custodian@database-a.example,database-b.example/opscustodian?sslmode=verify-full",
	}
	for _, dsn := range secure {
		if err := validateDatabaseTransport(dsn, false); err != nil {
			t.Errorf("secure DSN rejected: %v", err)
		}
	}

	insecure := []string{
		"postgres://custodian@database.example/opscustodian",
		"postgres://custodian@database.example/opscustodian?sslmode=disable",
		"postgres://custodian@database.example/opscustodian?sslmode=prefer",
		"postgres://custodian@database.example/opscustodian?sslmode=require",
		"postgres://custodian@database.example/opscustodian?sslmode=verify-ca",
	}
	for _, dsn := range insecure {
		if err := validateDatabaseTransport(dsn, false); err == nil || !strings.Contains(err.Error(), "verify-full") {
			t.Errorf("insecure DSN error = %v", err)
		}
	}
}

func TestDatabaseTransportAllowsExplicitDevelopmentOverride(t *testing.T) {
	if err := validateDatabaseTransport("postgres://custodian@127.0.0.1/opscustodian?sslmode=disable", true); err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseTransportErrorsNeverExposeCredentials(t *testing.T) {
	secret := "credential-that-must-not-escape"
	err := validateDatabaseTransport("postgres://custodian:"+secret+"@%zz", false)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("sanitized parse error = %v", err)
	}
}

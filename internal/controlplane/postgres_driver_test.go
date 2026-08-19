package controlplane

import (
	"database/sql"
	"testing"
)

func TestPostgresDriverIsRegisteredAndBuildsSQLDependencies(t *testing.T) {
	registered := false
	for _, name := range sql.Drivers() {
		if name == postgresDriverName {
			registered = true
			break
		}
	}
	if !registered {
		t.Fatalf("registered SQL drivers = %v; expected %q", sql.Drivers(), postgresDriverName)
	}
	dependencies, err := PostgresDependencies()
	if err != nil {
		t.Fatal(err)
	}
	database, err := dependencies.Open("postgres://custodian@127.0.0.1/opscustodian?sslmode=verify-full")
	if err != nil {
		t.Fatalf("construct pgx database handle without connecting: %v", err)
	}
	if err := dependencies.Close(database); err != nil {
		t.Fatalf("close unopened database handle: %v", err)
	}
}

package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/opscustodian/opscustodian/internal/store"
)

func TestBootstrapOrdersDatabaseLifecycleAndClosesOnce(t *testing.T) {
	config := validRuntimeConfig()
	var events []string
	database := &sql.DB{}
	dependencies := Dependencies{
		Open: func(dsn string) (*sql.DB, error) {
			if dsn != config.DatabaseDSN {
				t.Fatalf("Open() received unexpected DSN")
			}
			events = append(events, "open")
			return database, nil
		},
		Ping: func(ctx context.Context, value *sql.DB) error {
			if value != database {
				t.Fatal("Ping() received another database")
			}
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > config.ConnectTimeout {
				t.Fatal("Ping() did not receive a bounded context")
			}
			events = append(events, "ping")
			return nil
		},
		Migrate: func(ctx context.Context, _ *sql.DB) error {
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > config.MigrationTimeout {
				t.Fatal("Migrate() did not receive a bounded context")
			}
			events = append(events, "migrate")
			return nil
		},
		BuildStore: func(_ *sql.DB, organizationID, displayName string) (SnapshotStore, error) {
			if organizationID != config.OrganizationID || displayName != config.OrganizationDisplayName {
				t.Fatalf("BuildStore() identity = %q, %q", organizationID, displayName)
			}
			events = append(events, "store")
			return store.NewMemory(), nil
		},
		Close: func(*sql.DB) error {
			events = append(events, "close")
			return nil
		},
	}
	runtime, err := Bootstrap(context.Background(), config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Store == nil || !reflect.DeepEqual(events, []string{"open", "ping", "migrate", "store"}) {
		t.Fatalf("bootstrap events = %#v", events)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(events, []string{"open", "ping", "migrate", "store", "close"}) {
		t.Fatalf("close events = %#v", events)
	}
}

func TestBootstrapCanSkipMigrations(t *testing.T) {
	config := validRuntimeConfig()
	config.ApplyMigrations = false
	migrated := false
	dependencies := successfulDependencies()
	dependencies.Migrate = func(context.Context, *sql.DB) error { migrated = true; return nil }
	runtime, err := Bootstrap(context.Background(), config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if migrated {
		t.Fatal("migration ran when explicitly disabled")
	}
}

func TestBootstrapClosesDatabaseAfterEveryPostOpenFailure(t *testing.T) {
	tests := []struct {
		name string
		fail func(*Dependencies)
		want string
	}{
		{"ping", func(value *Dependencies) {
			value.Ping = func(context.Context, *sql.DB) error { return errors.New("ping failure") }
		}, "connect to PostgreSQL"},
		{"migration", func(value *Dependencies) {
			value.Migrate = func(context.Context, *sql.DB) error { return errors.New("migration failure") }
		}, "migrate PostgreSQL"},
		{"store", func(value *Dependencies) {
			value.BuildStore = func(*sql.DB, string, string) (SnapshotStore, error) { return nil, errors.New("store failure") }
		}, "initialize PostgreSQL store"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := successfulDependencies()
			closed := 0
			dependencies.Close = func(*sql.DB) error { closed++; return nil }
			test.fail(&dependencies)
			_, err := Bootstrap(context.Background(), validRuntimeConfig(), dependencies)
			if err == nil || !strings.Contains(err.Error(), test.want) || closed != 1 {
				t.Fatalf("Bootstrap() error = %v, closed = %d", err, closed)
			}
		})
	}
}

func TestBootstrapRejectsInvalidInputsBeforeOpeningDatabase(t *testing.T) {
	dependencies := successfulDependencies()
	opened := false
	dependencies.Open = func(string) (*sql.DB, error) { opened = true; return &sql.DB{}, nil }
	config := validRuntimeConfig()
	config.MaxOpenConns = 0
	if _, err := Bootstrap(context.Background(), config, dependencies); err == nil || opened {
		t.Fatalf("invalid configuration error = %v, opened = %v", err, opened)
	}
	if _, err := Bootstrap(context.Background(), validRuntimeConfig(), Dependencies{}); err == nil {
		t.Fatal("incomplete dependencies were accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Bootstrap(cancelled, validRuntimeConfig(), dependencies); !errors.Is(err, context.Canceled) || opened {
		t.Fatalf("cancelled bootstrap error = %v, opened = %v", err, opened)
	}
}

func successfulDependencies() Dependencies {
	return Dependencies{
		Open:    func(string) (*sql.DB, error) { return &sql.DB{}, nil },
		Ping:    func(context.Context, *sql.DB) error { return nil },
		Migrate: func(context.Context, *sql.DB) error { return nil },
		BuildStore: func(*sql.DB, string, string) (SnapshotStore, error) {
			return store.NewMemory(), nil
		},
		Close: func(*sql.DB) error { return nil },
	}
}

func validRuntimeConfig() Config {
	return Config{
		OrganizationID: "organization-0123456789abcdef", OrganizationDisplayName: "Agent Platform",
		DatabaseDSN: "postgres://database/controlplane", AllowInsecureDatabase: true, ApplyMigrations: true,
		ConnectTimeout: 5 * time.Second, ShutdownTimeout: 10 * time.Second,
		MigrationTimeout: 2 * time.Minute,
		MaxOpenConns:     20, MaxIdleConns: 5, ConnMaxLifetime: 30 * time.Minute,
		HTTP: defaultHTTPConfig(),
	}
}

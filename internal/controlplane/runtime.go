package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"

	"github.com/opscustodian/opscustodian/internal/migrations"
	"github.com/opscustodian/opscustodian/internal/store"
)

type SnapshotStore interface {
	store.Reader
	store.Writer
	store.SchedulerLeaseStore
	store.AuditStore
}

type Dependencies struct {
	Open       func(string) (*sql.DB, error)
	Ping       func(context.Context, *sql.DB) error
	Migrate    func(context.Context, *sql.DB) error
	BuildStore func(*sql.DB, string, string) (SnapshotStore, error)
	Close      func(*sql.DB) error
}

type Runtime struct {
	Store SnapshotStore

	database *sql.DB
	ping     func(context.Context, *sql.DB) error
	close    func(*sql.DB) error
	once     sync.Once
	closeErr error
}

func SQLDependencies(driverName string) (Dependencies, error) {
	if strings.TrimSpace(driverName) == "" {
		return Dependencies{}, fmt.Errorf("database driver name is required")
	}
	return Dependencies{
		Open:    func(dsn string) (*sql.DB, error) { return sql.Open(driverName, dsn) },
		Ping:    func(ctx context.Context, database *sql.DB) error { return database.PingContext(ctx) },
		Migrate: migrations.Apply,
		BuildStore: func(database *sql.DB, organizationID, displayName string) (SnapshotStore, error) {
			return store.NewPostgres(database, organizationID, displayName)
		},
		Close: func(database *sql.DB) error { return database.Close() },
	}, nil
}

func Bootstrap(ctx context.Context, config Config, dependencies Dependencies) (*Runtime, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := validateDependencies(dependencies); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	database, err := dependencies.Open(config.DatabaseDSN)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL database: %w", err)
	}
	if database == nil {
		return nil, fmt.Errorf("open PostgreSQL database: dependency returned nil database")
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = dependencies.Close(database)
		}
	}()

	database.SetMaxOpenConns(config.MaxOpenConns)
	database.SetMaxIdleConns(config.MaxIdleConns)
	database.SetConnMaxLifetime(config.ConnMaxLifetime)

	connectContext, cancel := context.WithTimeout(ctx, config.ConnectTimeout)
	err = dependencies.Ping(connectContext, database)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("connect to PostgreSQL database: %w", err)
	}
	if config.ApplyMigrations {
		migrationContext, cancel := context.WithTimeout(ctx, config.MigrationTimeout)
		err := dependencies.Migrate(migrationContext, database)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("migrate PostgreSQL database: %w", err)
		}
	}
	snapshotStore, err := dependencies.BuildStore(database, config.OrganizationID, config.OrganizationDisplayName)
	if err != nil {
		return nil, fmt.Errorf("initialize PostgreSQL store: %w", err)
	}
	if snapshotStore == nil {
		return nil, fmt.Errorf("initialize PostgreSQL store: dependency returned nil store")
	}
	cleanup = false
	return &Runtime{Store: snapshotStore, database: database, ping: dependencies.Ping, close: dependencies.Close}, nil
}

func (runtime *Runtime) Ping(ctx context.Context) error {
	if runtime == nil || runtime.database == nil || runtime.ping == nil {
		return fmt.Errorf("PostgreSQL runtime is not initialized")
	}
	return runtime.ping(ctx, runtime.database)
}

func (runtime *Runtime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.once.Do(func() {
		if runtime.database != nil && runtime.close != nil {
			runtime.closeErr = runtime.close(runtime.database)
		}
	})
	return runtime.closeErr
}

func validateDependencies(dependencies Dependencies) error {
	if dependencies.Open == nil || dependencies.Ping == nil || dependencies.Migrate == nil || dependencies.BuildStore == nil || dependencies.Close == nil {
		return fmt.Errorf("complete control-plane database dependencies are required")
	}
	return nil
}

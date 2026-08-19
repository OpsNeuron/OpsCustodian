package controlplane

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/opscustodian/opscustodian/internal/store"
)

const (
	defaultConnectTimeout   = 5 * time.Second
	defaultMigrationTimeout = 2 * time.Minute
	defaultShutdownTimeout  = 10 * time.Second
	defaultMaxOpenConns     = 20
	defaultMaxIdleConns     = 5
	defaultConnMaxLifetime  = 30 * time.Minute
)

type LookupEnv func(string) (string, bool)

type Config struct {
	OrganizationID          string
	OrganizationDisplayName string
	DatabaseDSN             string
	ApplyMigrations         bool
	ConnectTimeout          time.Duration
	MigrationTimeout        time.Duration
	ShutdownTimeout         time.Duration
	MaxOpenConns            int
	MaxIdleConns            int
	ConnMaxLifetime         time.Duration
}

type SafeConfig struct {
	OrganizationID          string        `json:"organizationId"`
	OrganizationDisplayName string        `json:"organizationDisplayName"`
	DatabaseConfigured      bool          `json:"databaseConfigured"`
	ApplyMigrations         bool          `json:"applyMigrations"`
	ConnectTimeout          time.Duration `json:"connectTimeout"`
	MigrationTimeout        time.Duration `json:"migrationTimeout"`
	ShutdownTimeout         time.Duration `json:"shutdownTimeout"`
	MaxOpenConns            int           `json:"maxOpenConnections"`
	MaxIdleConns            int           `json:"maxIdleConnections"`
	ConnMaxLifetime         time.Duration `json:"connectionMaxLifetime"`
}

func ConfigFromEnvironment(lookup LookupEnv) (Config, error) {
	if lookup == nil {
		return Config{}, fmt.Errorf("environment lookup is required")
	}
	config := Config{
		OrganizationID:          environmentValue(lookup, "OPSCUSTODIAN_ORGANIZATION_ID"),
		OrganizationDisplayName: environmentValue(lookup, "OPSCUSTODIAN_ORGANIZATION_DISPLAY_NAME"),
		DatabaseDSN:             environmentValue(lookup, "OPSCUSTODIAN_DATABASE_DSN"),
		ApplyMigrations:         true,
		ConnectTimeout:          defaultConnectTimeout,
		MigrationTimeout:        defaultMigrationTimeout,
		ShutdownTimeout:         defaultShutdownTimeout,
		MaxOpenConns:            defaultMaxOpenConns,
		MaxIdleConns:            defaultMaxIdleConns,
		ConnMaxLifetime:         defaultConnMaxLifetime,
	}
	if config.OrganizationDisplayName == "" {
		config.OrganizationDisplayName = config.OrganizationID
	}
	var err error
	if config.ApplyMigrations, err = environmentBool(lookup, "OPSCUSTODIAN_DATABASE_MIGRATE", config.ApplyMigrations); err != nil {
		return Config{}, err
	}
	if config.ConnectTimeout, err = environmentDuration(lookup, "OPSCUSTODIAN_DATABASE_CONNECT_TIMEOUT", config.ConnectTimeout); err != nil {
		return Config{}, err
	}
	if config.ShutdownTimeout, err = environmentDuration(lookup, "OPSCUSTODIAN_SHUTDOWN_TIMEOUT", config.ShutdownTimeout); err != nil {
		return Config{}, err
	}
	if config.MigrationTimeout, err = environmentDuration(lookup, "OPSCUSTODIAN_DATABASE_MIGRATION_TIMEOUT", config.MigrationTimeout); err != nil {
		return Config{}, err
	}
	if config.ConnMaxLifetime, err = environmentDuration(lookup, "OPSCUSTODIAN_DATABASE_CONN_MAX_LIFETIME", config.ConnMaxLifetime); err != nil {
		return Config{}, err
	}
	if config.MaxOpenConns, err = environmentInt(lookup, "OPSCUSTODIAN_DATABASE_MAX_OPEN_CONNS", config.MaxOpenConns); err != nil {
		return Config{}, err
	}
	if config.MaxIdleConns, err = environmentInt(lookup, "OPSCUSTODIAN_DATABASE_MAX_IDLE_CONNS", config.MaxIdleConns); err != nil {
		return Config{}, err
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (config Config) Validate() error {
	if !store.ValidOrganizationID(config.OrganizationID) {
		return fmt.Errorf("invalid OPSCUSTODIAN_ORGANIZATION_ID")
	}
	if strings.TrimSpace(config.OrganizationDisplayName) == "" || len(config.OrganizationDisplayName) > 200 {
		return fmt.Errorf("OPSCUSTODIAN_ORGANIZATION_DISPLAY_NAME must contain 1 to 200 characters")
	}
	if strings.TrimSpace(config.DatabaseDSN) == "" {
		return fmt.Errorf("OPSCUSTODIAN_DATABASE_DSN is required")
	}
	if config.ConnectTimeout <= 0 || config.ConnectTimeout > time.Minute {
		return fmt.Errorf("OPSCUSTODIAN_DATABASE_CONNECT_TIMEOUT must be between 1ns and 1m")
	}
	if config.ShutdownTimeout <= 0 || config.ShutdownTimeout > time.Minute {
		return fmt.Errorf("OPSCUSTODIAN_SHUTDOWN_TIMEOUT must be between 1ns and 1m")
	}
	if config.MigrationTimeout <= 0 || config.MigrationTimeout > 15*time.Minute {
		return fmt.Errorf("OPSCUSTODIAN_DATABASE_MIGRATION_TIMEOUT must be between 1ns and 15m")
	}
	if config.ConnMaxLifetime <= 0 || config.ConnMaxLifetime > 24*time.Hour {
		return fmt.Errorf("OPSCUSTODIAN_DATABASE_CONN_MAX_LIFETIME must be between 1ns and 24h")
	}
	if config.MaxOpenConns < 1 || config.MaxOpenConns > 1000 {
		return fmt.Errorf("OPSCUSTODIAN_DATABASE_MAX_OPEN_CONNS must be between 1 and 1000")
	}
	if config.MaxIdleConns < 0 || config.MaxIdleConns > config.MaxOpenConns {
		return fmt.Errorf("OPSCUSTODIAN_DATABASE_MAX_IDLE_CONNS must be between 0 and max open connections")
	}
	return nil
}

func (config Config) Safe() SafeConfig {
	return SafeConfig{
		OrganizationID: config.OrganizationID, OrganizationDisplayName: config.OrganizationDisplayName,
		DatabaseConfigured: config.DatabaseDSN != "", ApplyMigrations: config.ApplyMigrations,
		ConnectTimeout: config.ConnectTimeout, ShutdownTimeout: config.ShutdownTimeout,
		MigrationTimeout: config.MigrationTimeout,
		MaxOpenConns:     config.MaxOpenConns, MaxIdleConns: config.MaxIdleConns, ConnMaxLifetime: config.ConnMaxLifetime,
	}
}

func environmentValue(lookup LookupEnv, name string) string {
	value, _ := lookup(name)
	return strings.TrimSpace(value)
}

func environmentBool(lookup LookupEnv, name string, fallback bool) (bool, error) {
	value := environmentValue(lookup, name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", name)
	}
	return parsed, nil
}

func environmentDuration(lookup LookupEnv, name string, fallback time.Duration) (time.Duration, error) {
	value := environmentValue(lookup, name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a Go duration", name)
	}
	return parsed, nil
}

func environmentInt(lookup LookupEnv, name string, fallback int) (int, error) {
	value := environmentValue(lookup, name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", name)
	}
	return parsed, nil
}

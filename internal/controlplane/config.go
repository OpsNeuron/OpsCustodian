package controlplane

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/opscustodian/opscustodian/internal/server"
	"github.com/opscustodian/opscustodian/internal/store"
)

const (
	defaultConnectTimeout    = 5 * time.Second
	defaultMigrationTimeout  = 2 * time.Minute
	defaultShutdownTimeout   = 10 * time.Second
	defaultMaxOpenConns      = 20
	defaultMaxIdleConns      = 5
	defaultConnMaxLifetime   = 30 * time.Minute
	defaultListenAddress     = "127.0.0.1:8080"
	defaultReadHeaderTimeout = 5 * time.Second
	defaultReadTimeout       = 15 * time.Second
	defaultWriteTimeout      = 30 * time.Second
	defaultIdleTimeout       = 60 * time.Second
	defaultMaxHeaderBytes    = 64 << 10
	defaultSchedulerLeaseTTL = time.Minute
	defaultSchedulerRenewal  = 20 * time.Second
)

type LookupEnv func(string) (string, bool)

type Config struct {
	OrganizationID           string
	OrganizationDisplayName  string
	DatabaseDSN              string
	AllowInsecureDatabase    bool
	ApplyMigrations          bool
	ConnectTimeout           time.Duration
	MigrationTimeout         time.Duration
	ShutdownTimeout          time.Duration
	MaxOpenConns             int
	MaxIdleConns             int
	ConnMaxLifetime          time.Duration
	HTTP                     HTTPConfig
	Authenticator            server.BearerAuthenticator
	CredentialID             string
	CredentialIDs            []string
	Authorizer               server.ScopeAuthorizer
	CredentialRegistry       *server.CredentialRegistry
	CredentialFile           string
	CredentialReloadInterval time.Duration
	RepositorySetFile        string
	GitHubAppID              int64
	GitHubAppPrivateKeyFile  string
	SchedulerLeaseTTL        time.Duration
	SchedulerRenewInterval   time.Duration
}

type HTTPConfig struct {
	ListenAddress     string        `json:"listenAddress"`
	ReadHeaderTimeout time.Duration `json:"readHeaderTimeout"`
	ReadTimeout       time.Duration `json:"readTimeout"`
	WriteTimeout      time.Duration `json:"writeTimeout"`
	IdleTimeout       time.Duration `json:"idleTimeout"`
	MaxHeaderBytes    int           `json:"maxHeaderBytes"`
}

type SafeConfig struct {
	OrganizationID           string        `json:"organizationId"`
	OrganizationDisplayName  string        `json:"organizationDisplayName"`
	DatabaseConfigured       bool          `json:"databaseConfigured"`
	AllowInsecureDatabase    bool          `json:"allowInsecureDatabase"`
	ApplyMigrations          bool          `json:"applyMigrations"`
	ConnectTimeout           time.Duration `json:"connectTimeout"`
	MigrationTimeout         time.Duration `json:"migrationTimeout"`
	ShutdownTimeout          time.Duration `json:"shutdownTimeout"`
	MaxOpenConns             int           `json:"maxOpenConnections"`
	MaxIdleConns             int           `json:"maxIdleConnections"`
	ConnMaxLifetime          time.Duration `json:"connectionMaxLifetime"`
	HTTP                     HTTPConfig    `json:"http"`
	AuthenticationConfigured bool          `json:"authenticationConfigured"`
	CredentialID             string        `json:"credentialId"`
	CredentialIDs            []string      `json:"credentialIds"`
	AuthorizationScopes      []string      `json:"authorizationScopes"`
	CredentialFileConfigured bool          `json:"credentialFileConfigured"`
	CredentialReloadInterval time.Duration `json:"credentialReloadInterval,omitempty"`
	RepositorySetConfigured  bool          `json:"repositorySetConfigured"`
	GitHubAppConfigured      bool          `json:"githubAppConfigured"`
	SchedulerLeaseTTL        time.Duration `json:"schedulerLeaseTtl"`
	SchedulerRenewInterval   time.Duration `json:"schedulerRenewInterval"`
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
		SchedulerLeaseTTL:       defaultSchedulerLeaseTTL,
		SchedulerRenewInterval:  defaultSchedulerRenewal,
		HTTP:                    defaultHTTPConfig(),
	}
	var err error
	credentialsJSON := environmentValue(lookup, "OPSCUSTODIAN_API_CREDENTIALS")
	if credentialsJSON != "" {
		if environmentValue(lookup, "OPSCUSTODIAN_API_TOKEN") != "" || environmentValue(lookup, "OPSCUSTODIAN_API_TOKEN_ID") != "" || environmentValue(lookup, "OPSCUSTODIAN_API_SCOPES") != "" {
			return Config{}, fmt.Errorf("OPSCUSTODIAN_API_CREDENTIALS cannot be combined with single-token API variables")
		}
		credentials, parseErr := server.ParseBearerCredentialsJSON([]byte(credentialsJSON))
		if parseErr != nil {
			return Config{}, fmt.Errorf("invalid OPSCUSTODIAN_API_CREDENTIALS: %w", parseErr)
		}
		config.CredentialRegistry, err = server.NewCredentialRegistry(credentials)
		if err != nil {
			return Config{}, fmt.Errorf("invalid OPSCUSTODIAN_API_CREDENTIALS: %w", err)
		}
		config.Authenticator, config.Authorizer, err = config.CredentialRegistry.Security()
		if err != nil {
			return Config{}, err
		}
		config.CredentialIDs = config.Authenticator.CredentialIDs()
	} else {
		config.CredentialID = environmentValue(lookup, "OPSCUSTODIAN_API_TOKEN_ID")
		credential := server.BearerCredential{ID: config.CredentialID, Token: environmentValue(lookup, "OPSCUSTODIAN_API_TOKEN"), Scopes: environmentList(lookup, "OPSCUSTODIAN_API_SCOPES")}
		config.CredentialRegistry, err = server.NewCredentialRegistry([]server.BearerCredential{credential})
		if err != nil {
			return Config{}, fmt.Errorf("invalid OPSCUSTODIAN_API_TOKEN_ID, OPSCUSTODIAN_API_TOKEN, or OPSCUSTODIAN_API_SCOPES: %w", err)
		}
		config.Authenticator, config.Authorizer, err = config.CredentialRegistry.Security()
		if err != nil {
			return Config{}, err
		}
		config.CredentialIDs = config.Authenticator.CredentialIDs()
	}
	if config.OrganizationDisplayName == "" {
		config.OrganizationDisplayName = config.OrganizationID
	}
	config.CredentialFile = environmentValue(lookup, "OPSCUSTODIAN_API_CREDENTIAL_FILE")
	if config.CredentialFile != "" {
		if !filepath.IsAbs(config.CredentialFile) {
			return Config{}, fmt.Errorf("OPSCUSTODIAN_API_CREDENTIAL_FILE must be an absolute path")
		}
		config.CredentialReloadInterval, err = environmentDuration(lookup, "OPSCUSTODIAN_API_CREDENTIAL_RELOAD_INTERVAL", 30*time.Second)
		if err != nil {
			return Config{}, err
		}
	} else if environmentValue(lookup, "OPSCUSTODIAN_API_CREDENTIAL_RELOAD_INTERVAL") != "" {
		return Config{}, fmt.Errorf("OPSCUSTODIAN_API_CREDENTIAL_RELOAD_INTERVAL requires OPSCUSTODIAN_API_CREDENTIAL_FILE")
	}
	config.RepositorySetFile = environmentValue(lookup, "OPSCUSTODIAN_REPOSITORY_SET_FILE")
	if config.RepositorySetFile != "" && (!filepath.IsAbs(config.RepositorySetFile) || filepath.Clean(config.RepositorySetFile) != config.RepositorySetFile) {
		return Config{}, fmt.Errorf("OPSCUSTODIAN_REPOSITORY_SET_FILE must be a clean absolute path")
	}
	githubAppID := environmentValue(lookup, "OPSCUSTODIAN_GITHUB_APP_ID")
	config.GitHubAppPrivateKeyFile = environmentValue(lookup, "OPSCUSTODIAN_GITHUB_APP_PRIVATE_KEY_FILE")
	if githubAppID != "" || config.GitHubAppPrivateKeyFile != "" {
		if githubAppID == "" || config.GitHubAppPrivateKeyFile == "" {
			return Config{}, fmt.Errorf("OPSCUSTODIAN_GITHUB_APP_ID and OPSCUSTODIAN_GITHUB_APP_PRIVATE_KEY_FILE must be configured together")
		}
		config.GitHubAppID, err = strconv.ParseInt(githubAppID, 10, 64)
		if err != nil || config.GitHubAppID <= 0 {
			return Config{}, fmt.Errorf("OPSCUSTODIAN_GITHUB_APP_ID must be a positive integer")
		}
		if !filepath.IsAbs(config.GitHubAppPrivateKeyFile) || filepath.Clean(config.GitHubAppPrivateKeyFile) != config.GitHubAppPrivateKeyFile {
			return Config{}, fmt.Errorf("OPSCUSTODIAN_GITHUB_APP_PRIVATE_KEY_FILE must be a clean absolute path")
		}
	}
	if config.ApplyMigrations, err = environmentBool(lookup, "OPSCUSTODIAN_DATABASE_MIGRATE", config.ApplyMigrations); err != nil {
		return Config{}, err
	}
	if config.AllowInsecureDatabase, err = environmentBool(lookup, "OPSCUSTODIAN_DATABASE_ALLOW_INSECURE", false); err != nil {
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
	if config.SchedulerLeaseTTL, err = environmentDuration(lookup, "OPSCUSTODIAN_SCHEDULER_LEASE_TTL", config.SchedulerLeaseTTL); err != nil {
		return Config{}, err
	}
	if config.SchedulerRenewInterval, err = environmentDuration(lookup, "OPSCUSTODIAN_SCHEDULER_RENEW_INTERVAL", config.SchedulerRenewInterval); err != nil {
		return Config{}, err
	}
	if config.MaxOpenConns, err = environmentInt(lookup, "OPSCUSTODIAN_DATABASE_MAX_OPEN_CONNS", config.MaxOpenConns); err != nil {
		return Config{}, err
	}
	if config.MaxIdleConns, err = environmentInt(lookup, "OPSCUSTODIAN_DATABASE_MAX_IDLE_CONNS", config.MaxIdleConns); err != nil {
		return Config{}, err
	}
	config.HTTP.ListenAddress = environmentValueOr(lookup, "OPSCUSTODIAN_HTTP_LISTEN_ADDRESS", config.HTTP.ListenAddress)
	if config.HTTP.ReadHeaderTimeout, err = environmentDuration(lookup, "OPSCUSTODIAN_HTTP_READ_HEADER_TIMEOUT", config.HTTP.ReadHeaderTimeout); err != nil {
		return Config{}, err
	}
	if config.HTTP.ReadTimeout, err = environmentDuration(lookup, "OPSCUSTODIAN_HTTP_READ_TIMEOUT", config.HTTP.ReadTimeout); err != nil {
		return Config{}, err
	}
	if config.HTTP.WriteTimeout, err = environmentDuration(lookup, "OPSCUSTODIAN_HTTP_WRITE_TIMEOUT", config.HTTP.WriteTimeout); err != nil {
		return Config{}, err
	}
	if config.HTTP.IdleTimeout, err = environmentDuration(lookup, "OPSCUSTODIAN_HTTP_IDLE_TIMEOUT", config.HTTP.IdleTimeout); err != nil {
		return Config{}, err
	}
	if config.HTTP.MaxHeaderBytes, err = environmentInt(lookup, "OPSCUSTODIAN_HTTP_MAX_HEADER_BYTES", config.HTTP.MaxHeaderBytes); err != nil {
		return Config{}, err
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func defaultHTTPConfig() HTTPConfig {
	return HTTPConfig{
		ListenAddress: defaultListenAddress, ReadHeaderTimeout: defaultReadHeaderTimeout,
		ReadTimeout: defaultReadTimeout, WriteTimeout: defaultWriteTimeout,
		IdleTimeout: defaultIdleTimeout, MaxHeaderBytes: defaultMaxHeaderBytes,
	}
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
	if err := validateDatabaseTransport(config.DatabaseDSN, config.AllowInsecureDatabase); err != nil {
		return err
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
	if config.SchedulerLeaseTTL < store.MinimumLeaseTTL || config.SchedulerLeaseTTL > store.MaximumLeaseTTL {
		return fmt.Errorf("OPSCUSTODIAN_SCHEDULER_LEASE_TTL must be between 15s and 24h")
	}
	if config.SchedulerRenewInterval <= 0 || config.SchedulerRenewInterval >= config.SchedulerLeaseTTL {
		return fmt.Errorf("OPSCUSTODIAN_SCHEDULER_RENEW_INTERVAL must be positive and less than OPSCUSTODIAN_SCHEDULER_LEASE_TTL")
	}
	if err := config.HTTP.Validate(); err != nil {
		return err
	}
	if !config.Authenticator.Configured() {
		return fmt.Errorf("OPSCUSTODIAN_API_TOKEN is required")
	}
	if len(config.CredentialIDs) == 0 {
		config.CredentialIDs = config.Authenticator.CredentialIDs()
	}
	if len(config.CredentialIDs) == 0 || (config.CredentialID != "" && config.Authenticator.CredentialID() != config.CredentialID) {
		return fmt.Errorf("OPSCUSTODIAN_API_TOKEN_ID must match the configured credential")
	}
	if !config.Authorizer.Configured() {
		return fmt.Errorf("OPSCUSTODIAN_API_SCOPES is required")
	}
	if config.CredentialFile != "" && (config.CredentialReloadInterval < server.MinimumCredentialReloadInterval || config.CredentialReloadInterval > server.MaximumCredentialReloadInterval) {
		return fmt.Errorf("OPSCUSTODIAN_API_CREDENTIAL_RELOAD_INTERVAL must be between 1s and 1h")
	}
	if config.CredentialFile != "" && config.CredentialRegistry == nil {
		return fmt.Errorf("credential file reload requires a configured credential registry")
	}
	if config.RepositorySetFile != "" && (!filepath.IsAbs(config.RepositorySetFile) || filepath.Clean(config.RepositorySetFile) != config.RepositorySetFile) {
		return fmt.Errorf("OPSCUSTODIAN_REPOSITORY_SET_FILE must be a clean absolute path")
	}
	if (config.GitHubAppID == 0) != (config.GitHubAppPrivateKeyFile == "") {
		return fmt.Errorf("GitHub App ID and private key file must be configured together")
	}
	if config.GitHubAppID < 0 || (config.GitHubAppPrivateKeyFile != "" && (!filepath.IsAbs(config.GitHubAppPrivateKeyFile) || filepath.Clean(config.GitHubAppPrivateKeyFile) != config.GitHubAppPrivateKeyFile)) {
		return fmt.Errorf("GitHub App configuration is invalid")
	}
	return nil
}

func (config Config) Safe() SafeConfig {
	return SafeConfig{
		OrganizationID: config.OrganizationID, OrganizationDisplayName: config.OrganizationDisplayName,
		DatabaseConfigured: config.DatabaseDSN != "", AllowInsecureDatabase: config.AllowInsecureDatabase,
		ApplyMigrations: config.ApplyMigrations,
		ConnectTimeout:  config.ConnectTimeout, ShutdownTimeout: config.ShutdownTimeout,
		MigrationTimeout: config.MigrationTimeout,
		MaxOpenConns:     config.MaxOpenConns, MaxIdleConns: config.MaxIdleConns, ConnMaxLifetime: config.ConnMaxLifetime,
		HTTP:                     config.HTTP,
		AuthenticationConfigured: config.Authenticator.Configured(),
		CredentialID:             config.CredentialID,
		CredentialIDs:            append([]string(nil), config.CredentialIDs...),
		AuthorizationScopes:      config.Authorizer.Scopes(),
		CredentialFileConfigured: config.CredentialFile != "",
		CredentialReloadInterval: config.CredentialReloadInterval,
		RepositorySetConfigured:  config.RepositorySetFile != "",
		GitHubAppConfigured:      config.GitHubAppID > 0,
		SchedulerLeaseTTL:        config.SchedulerLeaseTTL,
		SchedulerRenewInterval:   config.SchedulerRenewInterval,
	}
}

func environmentList(lookup LookupEnv, name string) []string {
	value := environmentValue(lookup, name)
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func environmentValueOr(lookup LookupEnv, name, fallback string) string {
	if value := environmentValue(lookup, name); value != "" {
		return value
	}
	return fallback
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

package controlplane

import (
	"crypto/tls"
	"fmt"

	"github.com/jackc/pgx/v5"
)

func validateDatabaseTransport(dsn string, allowInsecure bool) error {
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("OPSCUSTODIAN_DATABASE_DSN is invalid")
	}
	if allowInsecure {
		return nil
	}
	if !verifiedTLS(config.Config.TLSConfig) {
		return secureDatabaseTransportError()
	}
	for _, fallback := range config.Config.Fallbacks {
		if !verifiedTLS(fallback.TLSConfig) {
			return secureDatabaseTransportError()
		}
	}
	return nil
}

func verifiedTLS(config *tls.Config) bool {
	return config != nil && !config.InsecureSkipVerify && config.ServerName != ""
}

func secureDatabaseTransportError() error {
	return fmt.Errorf("OPSCUSTODIAN_DATABASE_DSN must require certificate and hostname verification; use sslmode=verify-full or explicitly set OPSCUSTODIAN_DATABASE_ALLOW_INSECURE=true for isolated development")
}

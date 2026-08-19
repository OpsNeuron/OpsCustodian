package controlplane

import (
	_ "github.com/jackc/pgx/v5/stdlib"
)

const postgresDriverName = "pgx"

func PostgresDependencies() (Dependencies, error) {
	return SQLDependencies(postgresDriverName)
}

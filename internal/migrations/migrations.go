package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

//go:embed sql/*.sql
var files embed.FS

const advisoryLockID int64 = 724593128145

const bootstrap = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version bigint PRIMARY KEY,
    name text NOT NULL,
    checksum text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
)`

type Migration struct {
	Version  int64
	Name     string
	Up       string
	Down     string
	Checksum string
}

func Catalog() ([]Migration, error) {
	entries, err := fs.ReadDir(files, "sql")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}
	type pair struct{ up, down string }
	pairs := map[string]pair{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		base, direction, ok := strings.Cut(name, ".")
		if !ok || (direction != "up.sql" && direction != "down.sql") {
			return nil, fmt.Errorf("invalid migration filename %q", name)
		}
		content, err := files.ReadFile("sql/" + name)
		if err != nil {
			return nil, err
		}
		value := pairs[base]
		if direction == "up.sql" {
			value.up = string(content)
		} else {
			value.down = string(content)
		}
		pairs[base] = value
	}
	result := make([]Migration, 0, len(pairs))
	for base, pair := range pairs {
		versionText, name, ok := strings.Cut(base, "_")
		version, err := strconv.ParseInt(versionText, 10, 64)
		if !ok || err != nil || version <= 0 || name == "" || pair.up == "" || pair.down == "" {
			return nil, fmt.Errorf("incomplete migration %q", base)
		}
		sum := sha256.Sum256([]byte(pair.up))
		result = append(result, Migration{Version: version, Name: name, Up: pair.up, Down: pair.down, Checksum: fmt.Sprintf("sha256:%x", sum[:])})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Version < result[j].Version })
	for index, migration := range result {
		if migration.Version != int64(index+1) {
			return nil, fmt.Errorf("migration versions must be contiguous from 1; found %d at position %d", migration.Version, index+1)
		}
	}
	return result, nil
}

func Apply(ctx context.Context, database *sql.DB) error {
	catalog, err := Catalog()
	if err != nil {
		return err
	}
	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockID); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, bootstrap); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	applied, err := appliedMigrations(ctx, transaction)
	if err != nil {
		return err
	}
	if err := validateApplied(catalog, applied); err != nil {
		return err
	}
	for _, migration := range catalog {
		if _, exists := applied[migration.Version]; exists {
			continue
		}
		if _, err := transaction.ExecContext(ctx, migration.Up); err != nil {
			return fmt.Errorf("apply migration %06d_%s: %w", migration.Version, migration.Name, err)
		}
		if _, err := transaction.ExecContext(ctx, `INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`, migration.Version, migration.Name, migration.Checksum); err != nil {
			return fmt.Errorf("record migration %d: %w", migration.Version, err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}
	return nil
}

func Rollback(ctx context.Context, database *sql.DB, steps int) error {
	if steps < 1 {
		return fmt.Errorf("rollback steps must be positive")
	}
	catalog, err := Catalog()
	if err != nil {
		return err
	}
	byVersion := map[int64]Migration{}
	for _, migration := range catalog {
		byVersion[migration.Version] = migration
	}
	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin rollback transaction: %w", err)
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockID); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	rows, err := transaction.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations ORDER BY version DESC LIMIT $1`, steps)
	if err != nil {
		return fmt.Errorf("read rollback plan: %w", err)
	}
	type applied struct {
		version  int64
		checksum string
	}
	var plan []applied
	for rows.Next() {
		var value applied
		if err := rows.Scan(&value.version, &value.checksum); err != nil {
			rows.Close()
			return err
		}
		plan = append(plan, value)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, value := range plan {
		migration, exists := byVersion[value.version]
		if !exists || migration.Checksum != value.checksum {
			return fmt.Errorf("cannot safely roll back migration %d", value.version)
		}
		if _, err := transaction.ExecContext(ctx, migration.Down); err != nil {
			return fmt.Errorf("roll back migration %d: %w", value.version, err)
		}
		if _, err := transaction.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = $1`, value.version); err != nil {
			return err
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit rollback: %w", err)
	}
	return nil
}

func validateApplied(catalog []Migration, applied map[int64]string) error {
	known := map[int64]Migration{}
	for _, migration := range catalog {
		known[migration.Version] = migration
	}
	for version, checksum := range applied {
		migration, exists := known[version]
		if !exists {
			return fmt.Errorf("database contains unknown migration %d; use a compatible newer OpsCustodian binary", version)
		}
		if checksum != migration.Checksum {
			return fmt.Errorf("migration %d checksum mismatch", version)
		}
	}
	return nil
}

func appliedMigrations(ctx context.Context, transaction *sql.Tx) (map[int64]string, error) {
	rows, err := transaction.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("read migration ledger: %w", err)
	}
	defer rows.Close()
	result := map[int64]string{}
	for rows.Next() {
		var version int64
		var checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			return nil, err
		}
		result[version] = checksum
	}
	return result, rows.Err()
}

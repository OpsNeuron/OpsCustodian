package store

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"time"
)

const (
	MinimumLeaseTTL = 15 * time.Second
	MaximumLeaseTTL = 24 * time.Hour
)

var (
	leaseNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	holderIDPattern  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
)

const acquireSchedulerLeaseSQL = `WITH ensured_organization AS (
    INSERT INTO organizations (id, display_name) VALUES ($1, $2)
    ON CONFLICT (id) DO UPDATE SET display_name = EXCLUDED.display_name
    RETURNING id
)
INSERT INTO scheduler_leases (organization_id, name, holder_id, fencing_token, expires_at)
SELECT id, $3, $4, 1, now() + $5::interval FROM ensured_organization
ON CONFLICT (organization_id, name) DO UPDATE SET
    holder_id = EXCLUDED.holder_id,
    fencing_token = CASE
        WHEN scheduler_leases.holder_id = EXCLUDED.holder_id THEN scheduler_leases.fencing_token
        ELSE scheduler_leases.fencing_token + 1
    END,
    expires_at = now() + $5::interval,
    updated_at = now()
WHERE scheduler_leases.expires_at <= now()
   OR scheduler_leases.holder_id = EXCLUDED.holder_id
RETURNING holder_id, fencing_token, expires_at`

const renewSchedulerLeaseSQL = `UPDATE scheduler_leases
SET expires_at = now() + $5::interval, updated_at = now()
WHERE organization_id = $1 AND name = $2 AND holder_id = $3 AND fencing_token = $4
  AND expires_at > now()
RETURNING holder_id, fencing_token, expires_at`

const releaseSchedulerLeaseSQL = `DELETE FROM scheduler_leases
WHERE organization_id = $1 AND name = $2 AND holder_id = $3 AND fencing_token = $4
RETURNING true`

type SchedulerLease struct {
	Name         string
	HolderID     string
	FencingToken int64
	ExpiresAt    time.Time
}

func (writer *Postgres) AcquireSchedulerLease(ctx context.Context, name, holderID string, ttl time.Duration) (SchedulerLease, bool, error) {
	if err := validateSchedulerLeaseInput(ctx, name, holderID, ttl); err != nil {
		return SchedulerLease{}, false, err
	}
	var lease SchedulerLease
	lease.Name = name
	err := writer.database.QueryRowContext(ctx, acquireSchedulerLeaseSQL,
		writer.organizationID, writer.organizationDisplayName, name, holderID, postgresInterval(ttl),
	).Scan(&lease.HolderID, &lease.FencingToken, &lease.ExpiresAt)
	if err == sql.ErrNoRows {
		return SchedulerLease{}, false, nil
	}
	if err != nil {
		return SchedulerLease{}, false, fmt.Errorf("acquire scheduler lease: %w", err)
	}
	return lease, true, nil
}

func (writer *Postgres) RenewSchedulerLease(ctx context.Context, lease SchedulerLease, ttl time.Duration) (SchedulerLease, bool, error) {
	if lease.FencingToken <= 0 {
		return SchedulerLease{}, false, fmt.Errorf("scheduler lease fencing token must be positive")
	}
	if err := validateSchedulerLeaseInput(ctx, lease.Name, lease.HolderID, ttl); err != nil {
		return SchedulerLease{}, false, err
	}
	var renewed SchedulerLease
	renewed.Name = lease.Name
	err := writer.database.QueryRowContext(ctx, renewSchedulerLeaseSQL,
		writer.organizationID, lease.Name, lease.HolderID, lease.FencingToken, postgresInterval(ttl),
	).Scan(&renewed.HolderID, &renewed.FencingToken, &renewed.ExpiresAt)
	if err == sql.ErrNoRows {
		return SchedulerLease{}, false, nil
	}
	if err != nil {
		return SchedulerLease{}, false, fmt.Errorf("renew scheduler lease: %w", err)
	}
	return renewed, true, nil
}

func (writer *Postgres) ReleaseSchedulerLease(ctx context.Context, lease SchedulerLease) (bool, error) {
	if lease.FencingToken <= 0 {
		return false, fmt.Errorf("scheduler lease fencing token must be positive")
	}
	if err := validateSchedulerLeaseIdentity(ctx, lease.Name, lease.HolderID); err != nil {
		return false, err
	}
	var released bool
	err := writer.database.QueryRowContext(ctx, releaseSchedulerLeaseSQL,
		writer.organizationID, lease.Name, lease.HolderID, lease.FencingToken,
	).Scan(&released)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("release scheduler lease: %w", err)
	}
	return released, nil
}

func validateSchedulerLeaseInput(ctx context.Context, name, holderID string, ttl time.Duration) error {
	if err := validateSchedulerLeaseIdentity(ctx, name, holderID); err != nil {
		return err
	}
	if ttl < MinimumLeaseTTL || ttl > MaximumLeaseTTL {
		return fmt.Errorf("scheduler lease TTL must be between %s and %s", MinimumLeaseTTL, MaximumLeaseTTL)
	}
	return nil
}

func validateSchedulerLeaseIdentity(ctx context.Context, name, holderID string) error {
	if ctx == nil {
		return fmt.Errorf("scheduler lease context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !leaseNamePattern.MatchString(name) {
		return fmt.Errorf("invalid scheduler lease name %q", name)
	}
	if !holderIDPattern.MatchString(holderID) {
		return fmt.Errorf("invalid scheduler lease holder ID")
	}
	return nil
}

func postgresInterval(duration time.Duration) string {
	return fmt.Sprintf("%d microseconds", duration.Microseconds())
}

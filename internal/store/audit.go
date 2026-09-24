package store

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/opscustodian/opscustodian/internal/audit"
)

const insertAuditEventSQL = `INSERT INTO audit_events
    (organization_id, occurred_at, event_name, severity_number, identity_id, repository_id, event)
VALUES ($1, $2::timestamptz, $3, $4, NULLIF($5, ''), NULLIF($6, ''), $7::jsonb)`

func (postgres *Postgres) Record(ctx context.Context, event audit.Event) error {
	payload, identityID, repositoryID, err := validateAuditEvent(event, postgres.organizationID)
	if err != nil {
		return err
	}
	transaction, err := postgres.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin audit event transaction: %w", err)
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, insertAuditEventSQL, postgres.organizationID, event.Timestamp, event.EventName, event.SeverityNumber, identityID, repositoryID, payload); err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return transaction.Commit()
}

func (memory *Memory) Record(ctx context.Context, event audit.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	payload, identityID, repositoryID, err := validateAuditEvent(event, "")
	if err != nil {
		return err
	}
	var cloned audit.Event
	if err := json.Unmarshal(payload, &cloned); err != nil {
		return err
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	memory.auditEvents = append(memory.auditEvents, AuditRecord{ID: int64(len(memory.auditEvents) + 1), RepositoryID: repositoryID, IdentityID: identityID, Event: cloned})
	return nil
}

func validateAuditEvent(event audit.Event, organizationID string) ([]byte, string, string, error) {
	if event.SchemaVersion != audit.SchemaVersion || event.EventName == "" || len(event.EventName) > 200 || event.SeverityNumber < 1 || event.SeverityNumber > 24 {
		return nil, "", "", fmt.Errorf("audit event contract is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, event.Timestamp); err != nil {
		return nil, "", "", fmt.Errorf("audit event timestamp is invalid")
	}
	identityID, _ := event.Attributes["opscustodian.identity.id"].(string)
	repositoryID, _ := event.Attributes["opscustodian.repository.id"].(string)
	eventOrganization, _ := event.Attributes["opscustodian.organization.id"].(string)
	if organizationID != "" && eventOrganization != organizationID {
		return nil, "", "", fmt.Errorf("audit event organization does not match store tenant")
	}
	if repositoryID != "" && !validRepositoryIDValue(repositoryID) {
		return nil, "", "", fmt.Errorf("audit event repository ID is invalid")
	}
	payload, err := json.Marshal(event)
	if err != nil || len(payload) > 64<<10 {
		return nil, "", "", fmt.Errorf("audit event payload is invalid or exceeds 64 KiB")
	}
	return payload, identityID, repositoryID, nil
}

func validRepositoryIDValue(value string) bool {
	return repositoryAuditIDPattern.MatchString(value)
}

var repositoryAuditIDPattern = regexp.MustCompile(`^repository-[0-9a-f]{16}$`)

func parseAuditCursor(value string) (int64, error) {
	if value == "" {
		return 0, nil
	}
	return strconv.ParseInt(value, 10, 64)
}

const listAuditEventsSQL = `SELECT id, COALESCE(repository_id, ''), COALESCE(identity_id, ''), event
FROM audit_events
WHERE organization_id = $1
  AND ($2::bigint = 0 OR id < $2)
  AND ($3 = '' OR repository_id = $3)
  AND (cardinality($4::text[]) = 0 OR repository_id = ANY($4::text[]))
  AND ($5 = '' OR event_name = $5)
  AND ($6 = '' OR identity_id = $6)
ORDER BY id DESC
LIMIT $7`

func (postgres *Postgres) ListAuditEvents(ctx context.Context, filter AuditFilter) (AuditPage, error) {
	cursor, err := parseAuditCursor(filter.Page.Cursor)
	if err != nil {
		return AuditPage{}, fmt.Errorf("invalid audit cursor")
	}
	limit := filter.Page.Limit
	if limit < 1 || limit > 200 {
		return AuditPage{}, fmt.Errorf("audit page limit must be between 1 and 200")
	}
	repositoryIDs := filter.RepositoryIDs
	if repositoryIDs == nil {
		repositoryIDs = []string{}
	}
	rows, err := postgres.database.QueryContext(ctx, listAuditEventsSQL, postgres.organizationID, cursor, filter.RepositoryID, repositoryIDs, filter.EventName, filter.IdentityID, limit+1)
	if err != nil {
		return AuditPage{}, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()
	result := AuditPage{Items: []AuditRecord{}}
	for rows.Next() {
		var record AuditRecord
		var payload []byte
		if err := rows.Scan(&record.ID, &record.RepositoryID, &record.IdentityID, &payload); err != nil {
			return AuditPage{}, err
		}
		if err := json.Unmarshal(payload, &record.Event); err != nil {
			return AuditPage{}, fmt.Errorf("decode stored audit event: %w", err)
		}
		result.Items = append(result.Items, record)
	}
	if err := rows.Err(); err != nil {
		return AuditPage{}, err
	}
	if len(result.Items) > limit {
		result.Items = result.Items[:limit]
		result.NextCursor = strconv.FormatInt(result.Items[len(result.Items)-1].ID, 10)
	}
	return result, nil
}

func (memory *Memory) ListAuditEvents(ctx context.Context, filter AuditFilter) (AuditPage, error) {
	if err := ctx.Err(); err != nil {
		return AuditPage{}, err
	}
	cursor, err := parseAuditCursor(filter.Page.Cursor)
	if err != nil || filter.Page.Limit < 1 || filter.Page.Limit > 200 {
		return AuditPage{}, fmt.Errorf("invalid audit page")
	}
	allowed := map[string]struct{}{}
	for _, id := range filter.RepositoryIDs {
		allowed[id] = struct{}{}
	}
	memory.mu.RLock()
	defer memory.mu.RUnlock()
	result := AuditPage{Items: []AuditRecord{}}
	for index := len(memory.auditEvents) - 1; index >= 0; index-- {
		record := memory.auditEvents[index]
		if cursor > 0 && record.ID >= cursor || filter.RepositoryID != "" && record.RepositoryID != filter.RepositoryID || filter.EventName != "" && record.Event.EventName != filter.EventName || filter.IdentityID != "" && record.IdentityID != filter.IdentityID {
			continue
		}
		if filter.RepositoryIDs != nil {
			if _, ok := allowed[record.RepositoryID]; !ok {
				continue
			}
		}
		result.Items = append(result.Items, record)
		if len(result.Items) == filter.Page.Limit+1 {
			break
		}
	}
	if len(result.Items) > filter.Page.Limit {
		result.Items = result.Items[:filter.Page.Limit]
		result.NextCursor = strconv.FormatInt(result.Items[len(result.Items)-1].ID, 10)
	}
	return result, nil
}

const pruneAuditEventsSQL = `WITH expired AS (
    SELECT id FROM audit_events
    WHERE organization_id = $1 AND occurred_at < $2
    ORDER BY id
    LIMIT $3
)
DELETE FROM audit_events
WHERE organization_id = $1 AND id IN (SELECT id FROM expired)`

func (postgres *Postgres) PruneAuditEvents(ctx context.Context, before time.Time, limit int) (int64, error) {
	if before.IsZero() || limit < 1 || limit > 10000 {
		return 0, fmt.Errorf("audit retention cutoff and batch limit are invalid")
	}
	transaction, err := postgres.database.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx, pruneAuditEventsSQL, postgres.organizationID, before.UTC(), limit)
	if err != nil {
		return 0, fmt.Errorf("prune audit events: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := transaction.Commit(); err != nil {
		return 0, err
	}
	return deleted, nil
}

func (memory *Memory) PruneAuditEvents(ctx context.Context, before time.Time, limit int) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if before.IsZero() || limit < 1 || limit > 10000 {
		return 0, fmt.Errorf("audit retention cutoff and batch limit are invalid")
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	kept := make([]AuditRecord, 0, len(memory.auditEvents))
	var deleted int64
	for _, record := range memory.auditEvents {
		occurred, err := time.Parse(time.RFC3339Nano, record.Event.Timestamp)
		if err == nil && occurred.Before(before) && deleted < int64(limit) {
			deleted++
			continue
		}
		kept = append(kept, record)
	}
	memory.auditEvents = kept
	return deleted, nil
}

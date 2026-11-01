ALTER TABLE audit_events ADD COLUMN event_id text;

WITH identified AS (
    SELECT organization_id, id,
           'audit-' || md5(organization_id || ':' || id::text || ':' || event::text) AS event_id
    FROM audit_events
)
UPDATE audit_events AS target
SET event_id = identified.event_id,
    event = jsonb_set(target.event, '{eventId}', to_jsonb(identified.event_id), true)
FROM identified
WHERE target.organization_id = identified.organization_id
  AND target.id = identified.id;

ALTER TABLE audit_events
    ALTER COLUMN event_id SET NOT NULL,
    ADD CONSTRAINT audit_events_event_id_format
        CHECK (event_id ~ '^audit-[0-9a-f]{32}$'),
    ADD CONSTRAINT audit_events_event_id_unique
        UNIQUE (organization_id, event_id);

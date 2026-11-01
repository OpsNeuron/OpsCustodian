ALTER TABLE audit_events
    DROP CONSTRAINT IF EXISTS audit_events_event_id_unique,
    DROP CONSTRAINT IF EXISTS audit_events_event_id_format;

UPDATE audit_events SET event = event - 'eventId';

ALTER TABLE audit_events DROP COLUMN IF EXISTS event_id;

CREATE TABLE audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY,
    organization_id text NOT NULL,
    occurred_at timestamptz NOT NULL,
    event_name text NOT NULL,
    severity_number integer NOT NULL,
    identity_id text,
    repository_id text,
    event jsonb NOT NULL,
    PRIMARY KEY (organization_id, id),
    CONSTRAINT audit_events_organization_fk FOREIGN KEY (organization_id)
        REFERENCES organizations (id) ON DELETE CASCADE,
    CONSTRAINT audit_events_name_length CHECK (length(event_name) BETWEEN 1 AND 200),
    CONSTRAINT audit_events_severity CHECK (severity_number BETWEEN 1 AND 24),
    CONSTRAINT audit_events_payload_object CHECK (jsonb_typeof(event) = 'object')
);

CREATE INDEX audit_events_timeline_idx
    ON audit_events (organization_id, id DESC);

CREATE INDEX audit_events_repository_timeline_idx
    ON audit_events (organization_id, repository_id, id DESC)
    WHERE repository_id IS NOT NULL;

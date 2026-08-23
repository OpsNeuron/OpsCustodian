CREATE TABLE scheduler_leases (
    organization_id text NOT NULL,
    name text NOT NULL,
    holder_id text NOT NULL,
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, name),
    CONSTRAINT scheduler_leases_organization_fk FOREIGN KEY (organization_id)
        REFERENCES organizations (id) ON DELETE CASCADE,
    CONSTRAINT scheduler_leases_name_format CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,127}$'),
    CONSTRAINT scheduler_leases_holder_format CHECK (holder_id ~ '^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$')
);

CREATE INDEX scheduler_leases_expiry_idx
    ON scheduler_leases (expires_at);

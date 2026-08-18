CREATE TABLE IF NOT EXISTS organizations (
    id text PRIMARY KEY,
    display_name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT organizations_id_format CHECK (id ~ '^organization-[0-9a-f]{16}$')
);

CREATE TABLE IF NOT EXISTS repositories (
    organization_id text NOT NULL,
    id text NOT NULL,
    source text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, id),
    UNIQUE (organization_id, source),
    CONSTRAINT repositories_organization_fk FOREIGN KEY (organization_id)
        REFERENCES organizations (id) ON DELETE RESTRICT,
    CONSTRAINT repositories_id_format CHECK (id ~ '^repository-[0-9a-f]{16}$')
);

CREATE TABLE IF NOT EXISTS snapshots (
    organization_id text NOT NULL,
    repository_id text NOT NULL,
    id text NOT NULL,
    revision text NOT NULL,
    generated_at timestamptz,
    ingested_at timestamptz NOT NULL DEFAULT now(),
    api_version text NOT NULL,
    normalization_version text,
    bom jsonb NOT NULL,
    PRIMARY KEY (organization_id, repository_id, id),
    UNIQUE (organization_id, repository_id, revision),
    CONSTRAINT snapshots_repository_fk FOREIGN KEY (organization_id, repository_id)
        REFERENCES repositories (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT snapshots_id_format CHECK (id ~ '^snapshot-[0-9a-f]{16}$'),
    CONSTRAINT snapshots_bom_object CHECK (jsonb_typeof(bom) = 'object'),
    CONSTRAINT snapshots_bom_version CHECK (bom ->> 'apiVersion' = api_version),
    CONSTRAINT snapshots_bom_revision CHECK (bom #>> '{metadata,revision}' = revision)
);

CREATE TABLE IF NOT EXISTS snapshot_findings (
    organization_id text NOT NULL,
    repository_id text NOT NULL,
    snapshot_id text NOT NULL,
    finding_id text NOT NULL,
    finding_type text NOT NULL,
    severity text NOT NULL,
    asset_id text NOT NULL,
    remediation_id text NOT NULL,
    finding jsonb NOT NULL,
    PRIMARY KEY (organization_id, repository_id, snapshot_id, finding_id),
    CONSTRAINT snapshot_findings_snapshot_fk FOREIGN KEY (organization_id, repository_id, snapshot_id)
        REFERENCES snapshots (organization_id, repository_id, id) ON DELETE CASCADE,
    CONSTRAINT snapshot_findings_severity CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    CONSTRAINT snapshot_findings_object CHECK (jsonb_typeof(finding) = 'object'),
    CONSTRAINT snapshot_findings_id CHECK (finding ->> 'id' = finding_id),
    CONSTRAINT snapshot_findings_remediation CHECK (finding ->> 'remediationId' = remediation_id)
);

CREATE INDEX snapshots_repository_history_idx
    ON snapshots (organization_id, repository_id, ingested_at DESC, id DESC);
CREATE INDEX snapshot_findings_current_query_idx
    ON snapshot_findings (organization_id, repository_id, severity, finding_id);
CREATE INDEX snapshot_findings_lifecycle_idx
    ON snapshot_findings (organization_id, repository_id, finding_id, snapshot_id);

CREATE FUNCTION opscustodian_reject_immutable_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'OpsCustodian immutable record cannot be updated';
END;
$$;

CREATE TRIGGER snapshots_immutable_update
    BEFORE UPDATE ON snapshots
    FOR EACH ROW EXECUTE FUNCTION opscustodian_reject_immutable_update();

CREATE TRIGGER snapshot_findings_immutable_update
    BEFORE UPDATE ON snapshot_findings
    FOR EACH ROW EXECUTE FUNCTION opscustodian_reject_immutable_update();

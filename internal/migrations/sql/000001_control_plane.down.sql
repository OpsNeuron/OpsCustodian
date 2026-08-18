DROP TRIGGER IF EXISTS snapshot_findings_immutable_update ON snapshot_findings;
DROP TRIGGER IF EXISTS snapshots_immutable_update ON snapshots;
DROP FUNCTION IF EXISTS opscustodian_reject_immutable_update();
DROP TABLE IF EXISTS snapshot_findings;
DROP TABLE IF EXISTS snapshots;
DROP TABLE IF EXISTS repositories;
DROP TABLE IF EXISTS organizations;

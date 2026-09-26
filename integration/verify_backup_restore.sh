#!/usr/bin/env sh
set -eu

integration_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

compose() {
  docker compose --project-directory "$integration_dir" -f "$integration_dir/compose.yaml" "$@"
}

: "${OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD:=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
: "${OPSCUSTODIAN_INTEGRATION_API_TOKEN:=integration-$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
export OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD OPSCUSTODIAN_INTEGRATION_API_TOKEN

cleanup() {
  if [ "${OPSCUSTODIAN_INTEGRATION_KEEP:-false}" != "true" ]; then
    compose --profile recovery down --volumes --remove-orphans
  fi
}
trap cleanup EXIT INT TERM

compose --profile recovery up --detach --build --wait postgres collector opscustodian postgres-restore

attempt=0
until compose exec -T opscustodian wget -q -O - http://127.0.0.1:8080/readyz | grep -q '"status":"ready"'; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "source control plane did not become ready" >&2
    exit 1
  fi
  sleep 1
done

# Freeze application writers so the verification fingerprint and logical dump
# describe the same recovery point.
compose stop opscustodian

source_fingerprint=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "
SELECT concat_ws(':',
  (SELECT count(*) FROM schema_migrations),
  (SELECT count(*) FROM organizations),
  (SELECT count(*) FROM repositories),
  (SELECT count(*) FROM snapshots),
  (SELECT count(*) FROM snapshot_findings),
  (SELECT count(*) FROM audit_events),
  COALESCE((SELECT md5(string_agg(repository_id || ':' || id || ':' || bom::text, '|' ORDER BY repository_id, id)) FROM snapshots), ''),
  COALESCE((SELECT md5(string_agg(id::text || ':' || event::text, '|' ORDER BY id)) FROM audit_events), '')
);")

compose exec -T postgres pg_dump --format=custom --no-owner --no-privileges -U opscustodian -d opscustodian |
  compose exec -T postgres-restore pg_restore --exit-on-error --no-owner --no-privileges -U opscustodian -d opscustodian

restored_fingerprint=$(compose exec -T postgres-restore psql -At -U opscustodian -d opscustodian -c "
SELECT concat_ws(':',
  (SELECT count(*) FROM schema_migrations),
  (SELECT count(*) FROM organizations),
  (SELECT count(*) FROM repositories),
  (SELECT count(*) FROM snapshots),
  (SELECT count(*) FROM snapshot_findings),
  (SELECT count(*) FROM audit_events),
  COALESCE((SELECT md5(string_agg(repository_id || ':' || id || ':' || bom::text, '|' ORDER BY repository_id, id)) FROM snapshots), ''),
  COALESCE((SELECT md5(string_agg(id::text || ':' || event::text, '|' ORDER BY id)) FROM audit_events), '')
);")

if [ "$source_fingerprint" != "$restored_fingerprint" ]; then
  echo "restored database fingerprint does not match source" >&2
  exit 1
fi

tenant_count=$(compose exec -T postgres-restore psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM organizations WHERE id = 'organization-0123456789abcdef';")
if [ "$tenant_count" != "1" ]; then
  echo "restored tenant boundary is missing or ambiguous" >&2
  exit 1
fi

compose --profile recovery up --detach --wait opscustodian-restore
compose exec -T -e OPSCUSTODIAN_TEST_API_TOKEN="$OPSCUSTODIAN_INTEGRATION_API_TOKEN" opscustodian-restore sh -c 'wget -q -O - --header="Authorization: Bearer $OPSCUSTODIAN_TEST_API_TOKEN" http://127.0.0.1:8080/api/v1/repositories' | grep -q 'integration:scan-input'

echo "OpsCustodian PostgreSQL backup and restore verification passed."

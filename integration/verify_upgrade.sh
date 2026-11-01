#!/usr/bin/env sh
set -eu

integration_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_dir=$(CDPATH= cd -- "$integration_dir/.." && pwd)
temporary_root=${TMPDIR:-/tmp}
source_context=$(mktemp -d "$temporary_root/opscustodian-upgrade.XXXXXX")
source_image="opscustodian-integration-upgrade-source:run-$$"

compose() {
  docker compose --project-directory "$integration_dir" -f "$integration_dir/compose.yaml" "$@"
}

: "${OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD:=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
: "${OPSCUSTODIAN_INTEGRATION_API_TOKEN:=integration-$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
export OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD OPSCUSTODIAN_INTEGRATION_API_TOKEN
export OPSCUSTODIAN_INTEGRATION_UPGRADE_SOURCE_IMAGE="$source_image"

cleanup() {
  if [ "${OPSCUSTODIAN_INTEGRATION_KEEP:-false}" != "true" ]; then
    compose --profile upgrade down --volumes --remove-orphans
    docker image rm "$source_image" >/dev/null 2>&1 || true
  fi
  case "$source_context" in
    "$temporary_root"/opscustodian-upgrade.*) rm -rf -- "$source_context" ;;
    *) echo "refusing to remove unexpected upgrade source path" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM

git -C "$repository_dir" archive v0.5.0-alpha | tar -x -C "$source_context"
docker build --tag "$source_image" "$source_context"

if ! compose --profile upgrade up --detach --wait postgres-upgrade opscustodian-upgrade-source; then
  compose logs opscustodian-upgrade-source >&2
  exit 1
fi

source_migrations=$(compose exec -T postgres-upgrade psql -At -U opscustodian -d opscustodian -c "SELECT string_agg(version::text, ',' ORDER BY version) FROM schema_migrations;")
source_snapshot_count=$(compose exec -T postgres-upgrade psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots;")
source_snapshot_digest=$(compose exec -T postgres-upgrade psql -At -U opscustodian -d opscustodian -c "SELECT md5(string_agg(repository_id || ':' || id || ':' || bom::text, '|' ORDER BY repository_id, id)) FROM snapshots;")
if [ "$source_migrations" != "1,2" ] || [ "$source_snapshot_count" -lt 1 ] || [ -z "$source_snapshot_digest" ]; then
  echo "source release did not create the expected version-2 database" >&2
  exit 1
fi

compose stop opscustodian-upgrade-source

# Materialize the previously released schema-3 state so the current binary
# must exercise migration 4 rather than creating audit history from scratch.
compose exec -T postgres-upgrade psql -v ON_ERROR_STOP=1 -U opscustodian -d opscustodian < "$repository_dir/internal/migrations/sql/000003_audit_history.up.sql"
compose exec -T postgres-upgrade psql -v ON_ERROR_STOP=1 -U opscustodian -d opscustodian -c "INSERT INTO schema_migrations (version, name, checksum) VALUES (3, 'audit_history', 'sha256:ed85e031d05ebc954145a014ecde35db84e92153215c66cd0e2b27e5b06adc64');"
compose exec -T postgres-upgrade psql -v ON_ERROR_STOP=1 -U opscustodian -d opscustodian <<'SQL'
INSERT INTO audit_events
    (organization_id, occurred_at, event_name, severity_number, event)
VALUES (
    'organization-0123456789abcdef',
    '2026-10-08T12:00:00Z',
    'opscustodian.credential.reload.completed',
    9,
    '{"schemaVersion":"opscustodian.dev/audit-event/v1alpha1","timestamp":"2026-10-08T12:00:00Z","eventName":"opscustodian.credential.reload.completed","severityNumber":9,"body":"Legacy audit fixture","resource":{"service.name":"opscustodian"},"instrumentationScope":{"name":"github.com/opscustodian/opscustodian/audit"},"attributes":{"opscustodian.organization.id":"organization-0123456789abcdef","opscustodian.credential.reload.result":"succeeded"}}'::jsonb
);
SQL

compose run --rm --no-deps --build --entrypoint sh opscustodian-upgrade-target -c 'chmod 700 /audit-spool'
compose --profile upgrade up --detach --build --wait opscustodian-upgrade-target

target_migrations=$(compose exec -T postgres-upgrade psql -At -U opscustodian -d opscustodian -c "SELECT string_agg(version::text, ',' ORDER BY version) FROM schema_migrations;")
target_snapshot_count=$(compose exec -T postgres-upgrade psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots;")
target_snapshot_digest=$(compose exec -T postgres-upgrade psql -At -U opscustodian -d opscustodian -c "SELECT md5(string_agg(repository_id || ':' || id || ':' || bom::text, '|' ORDER BY repository_id, id)) FROM snapshots;")
target_audit_backfill=$(compose exec -T postgres-upgrade psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM audit_events WHERE occurred_at = '2026-10-08T12:00:00Z'::timestamptz AND event->>'body' = 'Legacy audit fixture' AND event_id ~ '^audit-[0-9a-f]{32}$' AND event->>'eventId' = event_id;")
if [ "$target_migrations" != "1,2,3,4" ] || [ "$target_snapshot_count" != "$source_snapshot_count" ] || [ "$target_snapshot_digest" != "$source_snapshot_digest" ] || [ "$target_audit_backfill" != "1" ]; then
  echo "forward migration did not preserve snapshots or backfill audit identity" >&2
  exit 1
fi

# Prove restart replay and tenant-scoped idempotency with a real spool file.
compose stop opscustodian-upgrade-target
compose run --rm --no-deps --entrypoint sh opscustodian-upgrade-target -c 'cat > /audit-spool/audit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json <<"EOF"
{"schemaVersion":"opscustodian.dev/audit-event/v1alpha1","eventId":"audit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestamp":"2026-10-08T12:01:00Z","eventName":"opscustodian.credential.reload.completed","severityNumber":9,"body":"Spool replay fixture","resource":{"service.name":"opscustodian"},"instrumentationScope":{"name":"github.com/opscustodian/opscustodian/audit"},"attributes":{"opscustodian.organization.id":"organization-0123456789abcdef","opscustodian.credential.reload.result":"succeeded"}}
EOF
chmod 600 /audit-spool/audit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json'
compose --profile upgrade up --detach --wait opscustodian-upgrade-target
spooled_count=$(compose exec -T postgres-upgrade psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM audit_events WHERE event_id = 'audit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';")
compose restart opscustodian-upgrade-target
compose --profile upgrade up --detach --wait opscustodian-upgrade-target
replayed_count=$(compose exec -T postgres-upgrade psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM audit_events WHERE event_id = 'audit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';")
if [ "$spooled_count" != "1" ] || [ "$replayed_count" != "1" ] || compose exec -T opscustodian-upgrade-target test -e /audit-spool/audit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json; then
  echo "durable audit replay was not idempotent" >&2
  exit 1
fi

compose exec -T -e OPSCUSTODIAN_TEST_API_TOKEN="$OPSCUSTODIAN_INTEGRATION_API_TOKEN" opscustodian-upgrade-target sh -c 'wget -q -O - --header="Authorization: Bearer $OPSCUSTODIAN_TEST_API_TOKEN" http://127.0.0.1:8080/api/v1/repositories' | grep -q 'integration:scan-input'
compose restart opscustodian-upgrade-target
compose --profile upgrade up --detach --wait opscustodian-upgrade-target
idempotent_migrations=$(compose exec -T postgres-upgrade psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM schema_migrations;")
if [ "$idempotent_migrations" != "4" ]; then
  echo "migration reapplication changed the migration ledger" >&2
  exit 1
fi

compose stop opscustodian-upgrade-target
if downgrade_output=$(compose run --rm --no-deps opscustodian-upgrade-source 2>&1); then
  echo "older release unexpectedly accepted a newer database" >&2
  exit 1
fi
printf '%s\n' "$downgrade_output" | grep -q 'compatible newer OpsCustodian binary'

compose exec -T postgres-upgrade psql -v ON_ERROR_STOP=1 -U opscustodian -d opscustodian -c "INSERT INTO schema_migrations (version, name, checksum) VALUES (999, 'future_fixture', 'sha256:future');"
if future_output=$(compose run --rm --no-deps opscustodian-upgrade-target 2>&1); then
  echo "current release unexpectedly accepted an unknown future migration" >&2
  exit 1
fi
printf '%s\n' "$future_output" | grep -q 'compatible newer OpsCustodian binary'

echo "OpsCustodian PostgreSQL upgrade compatibility verification passed."

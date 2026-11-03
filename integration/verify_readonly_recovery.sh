#!/usr/bin/env sh
set -eu

integration_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

compose() {
  docker compose --project-directory "$integration_dir" -f "$integration_dir/compose.yaml" "$@"
}

: "${OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD:=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
: "${OPSCUSTODIAN_INTEGRATION_API_TOKEN:=integration-$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
export OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD OPSCUSTODIAN_INTEGRATION_API_TOKEN
export OPSCUSTODIAN_INTEGRATION_HEALTHCHECK_INTERVAL=2s

response_headers=$(mktemp)
read_only_enabled=false
cleanup() {
  rm -f "$response_headers"
  if [ "$read_only_enabled" = true ]; then
    compose exec -T postgres psql -v ON_ERROR_STOP=1 -U opscustodian -d postgres \
      -c 'ALTER DATABASE opscustodian RESET default_transaction_read_only;' >/dev/null 2>&1 || true
  fi
  if [ "${OPSCUSTODIAN_INTEGRATION_KEEP:-false}" != "true" ]; then
    compose --profile performance down --volumes --remove-orphans
  fi
}
trap cleanup EXIT INT TERM

if [ -n "${OPSCUSTODIAN_INTEGRATION_BUILD_PROXY:-}" ]; then
  compose --profile performance build \
    --build-arg HTTP_PROXY="$OPSCUSTODIAN_INTEGRATION_BUILD_PROXY" \
    --build-arg HTTPS_PROXY="$OPSCUSTODIAN_INTEGRATION_BUILD_PROXY" \
    opscustodian loadprobe
else
  compose --profile performance build opscustodian loadprobe
fi
compose run --rm --no-deps --entrypoint sh opscustodian -c 'chmod 700 /audit-spool'
compose up --detach --wait postgres collector opscustodian

# Preserve normal bootstrap so the organization exists, then isolate the
# explicit request from scheduled ingestion and automatic audited health
# requests. Startup is verified directly before read-only mode is enabled.
export OPSCUSTODIAN_INTEGRATION_REPOSITORY_SET_FILE=
export OPSCUSTODIAN_INTEGRATION_HEALTHCHECK_INTERVAL=10m
compose up --detach --force-recreate opscustodian
attempt=0
until compose ps --status running --services | grep -qx 'opscustodian'; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "control plane did not start before read-only injection" >&2
    compose logs opscustodian >&2
    exit 1
  fi
  sleep 1
done
attempt=0
until compose exec -T opscustodian sh -c 'wget -q -O - http://127.0.0.1:8080/healthz' | grep -q '"status":"ok"'; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "control plane did not become healthy before read-only injection" >&2
    compose logs opscustodian >&2
    exit 1
  fi
  sleep 1
done
compose exec -T opscustodian sh -c '
  sed "s/\"revision\": \"proposed\"/\"revision\": \"readonly-rejected\"/" \
    /fixtures/scope-expansion/agentbom.after.json > /work/readonly-rejected.json
'

compose exec -T postgres psql -v ON_ERROR_STOP=1 -U opscustodian -d postgres \
  -c 'ALTER DATABASE opscustodian SET default_transaction_read_only = on;' >/dev/null
read_only_enabled=true
compose exec -T postgres psql -v ON_ERROR_STOP=1 -U opscustodian -d postgres \
  -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'opscustodian' AND pid <> pg_backend_pid();" >/dev/null

transaction_mode=$(compose exec -T postgres psql -At -v ON_ERROR_STOP=1 -U opscustodian -d opscustodian -c 'SHOW transaction_read_only;')
if [ "$transaction_mode" != "on" ]; then
  echo "new PostgreSQL sessions did not enter read-only transaction mode" >&2
  exit 1
fi
read_only_select=$(compose exec -T postgres psql -At -v ON_ERROR_STOP=1 -U opscustodian -d opscustodian -c 'SELECT 1;')
if [ "$read_only_select" != "1" ]; then
  echo "read-only PostgreSQL did not remain reachable for queries" >&2
  exit 1
fi

# Allow the database monitor to reconnect. No HTTP probe is sent here because
# every public endpoint is intentionally audited and would be the failure
# trigger under a read-only audit store.
sleep 6
if ! compose ps --status running --services | grep -qx 'opscustodian'; then
  echo "control plane stopped before the explicit audited read-only write" >&2
  compose logs opscustodian >&2
  exit 1
fi

if compose exec -T -e OPSCUSTODIAN_TEST_API_TOKEN="$OPSCUSTODIAN_INTEGRATION_API_TOKEN" opscustodian sh -c '
  wget -S -O /dev/null \
    --header="Authorization: Bearer $OPSCUSTODIAN_TEST_API_TOKEN" \
    --header="Content-Type: application/json" \
    --post-file=/work/readonly-rejected.json \
    http://127.0.0.1:8080/api/v1/snapshots
' 2>"$response_headers"; then
  echo "snapshot write unexpectedly succeeded while PostgreSQL was read-only" >&2
  exit 1
fi
if ! grep -q 'HTTP/1.1 500' "$response_headers"; then
  echo "read-only snapshot write did not return the expected 500 response" >&2
  cat "$response_headers" >&2
  exit 1
fi

attempt=0
while compose ps --status running --services | grep -qx 'opscustodian'; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "control plane did not fail closed after read-only audit persistence failure" >&2
    compose logs opscustodian >&2
    exit 1
  fi
  sleep 1
done

spooled_event_ids=$(compose run --rm --no-deps --entrypoint sh opscustodian -c '
  found=false
  for path in /audit-spool/audit-*.json; do
    if [ -f "$path" ]; then
      found=true
      grep -q '"eventName":"opscustodian.http.request.completed"' "$path"
      grep -q '"http.response.status_code":500' "$path"
      grep -q '"opscustodian.snapshot.ingestion.result":"failed"' "$path"
      basename "$path" .json
    fi
  done
  if [ "$found" = false ]; then exit 1; fi
')
spooled_event_count=0
for event_id in $spooled_event_ids; do
  if ! printf '%s\n' "$event_id" | grep -Eq '^audit-[0-9a-f]{32}$'; then
    echo "read-only durable audit event ID is invalid" >&2
    exit 1
  fi
  spooled_event_count=$((spooled_event_count + 1))
done
if [ "$spooled_event_count" != "1" ]; then
  echo "unexpected read-only durable audit event count: $spooled_event_count" >&2
  exit 1
fi

rejected_snapshot_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots WHERE revision = 'readonly-rejected';")
if [ "$rejected_snapshot_count" != "0" ]; then
  echo "read-only rejected snapshot was partially persisted" >&2
  exit 1
fi

compose exec -T postgres psql -v ON_ERROR_STOP=1 -U opscustodian -d postgres \
  -c 'ALTER DATABASE opscustodian RESET default_transaction_read_only;' >/dev/null
read_only_enabled=false
export OPSCUSTODIAN_INTEGRATION_HEALTHCHECK_INTERVAL=2s
compose up --detach --force-recreate --wait opscustodian

for event_id in $spooled_event_ids; do
  replayed_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM audit_events WHERE event_id = '$event_id' AND event->'attributes'->>'opscustodian.snapshot.ingestion.result' = 'failed' AND event->'attributes'->>'http.response.status_code' = '500';")
  if [ "$replayed_count" != "1" ]; then
    echo "read-only durable event $event_id was not replayed exactly once with the expected outcome" >&2
    exit 1
  fi
done

pending_spool_count=$(compose run --rm --no-deps --entrypoint sh opscustodian -c '
  set -- /audit-spool/audit-*.json
  if [ -e "$1" ]; then echo "$#"; else echo 0; fi
')
if [ "$pending_spool_count" != "0" ]; then
  echo "durable spool was not empty after read-write recovery: $pending_spool_count" >&2
  exit 1
fi

recovery_summary=$(compose --profile performance run --rm --no-deps loadprobe \
  -duration-seconds 10 -read-workers 4 -write-workers 1 \
  -read-rps 20 -write-rps 2 -revision-prefix readonly-recovery)

write_success=$(printf '%s\n' "$recovery_summary" | sed -n 's/.*"write":{[^}]*"successes":\([0-9][0-9]*\).*/\1/p')
case "$write_success" in
  ''|*[!0-9]*) echo "read-only recovery probe returned an invalid write count" >&2; exit 1 ;;
esac
recovery_snapshot_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots WHERE revision LIKE 'readonly-recovery-%';")
orphan_findings=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshot_findings finding LEFT JOIN snapshots snapshot ON snapshot.organization_id = finding.organization_id AND snapshot.repository_id = finding.repository_id AND snapshot.id = finding.snapshot_id WHERE snapshot.id IS NULL;")
audit_identity_violations=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM audit_events WHERE event_id IS NULL OR event->>'eventId' IS DISTINCT FROM event_id;")
audit_duplicate_groups=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM (SELECT organization_id, event_id FROM audit_events GROUP BY organization_id, event_id HAVING count(*) > 1) duplicates;")
if [ "$recovery_snapshot_count" != "$write_success" ] || \
   [ "$orphan_findings" != "0" ] || \
   [ "$audit_identity_violations" != "0" ] || \
   [ "$audit_duplicate_groups" != "0" ]; then
  echo "read-only recovery integrity verification failed: recovery_snapshots=$recovery_snapshot_count recovery_writes=$write_success orphan_findings=$orphan_findings identity_violations=$audit_identity_violations duplicate_groups=$audit_duplicate_groups" >&2
  exit 1
fi

compose restart opscustodian
compose up --detach --wait opscustodian
for event_id in $spooled_event_ids; do
  restart_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM audit_events WHERE event_id = '$event_id';")
  if [ "$restart_count" != "1" ]; then
    echo "read-only durable event $event_id was duplicated after restart" >&2
    exit 1
  fi
done

printf 'OpsCustodian read-only recovery passed: transaction_read_only=on rejected_status=500 rejected_snapshots=%s spooled_events=%s recovery_snapshots=%s recovery=%s\n' \
  "$rejected_snapshot_count" "$spooled_event_count" "$recovery_snapshot_count" "$recovery_summary"

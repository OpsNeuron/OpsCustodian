#!/usr/bin/env sh
set -eu

integration_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

compose() {
  docker compose --project-directory "$integration_dir" -f "$integration_dir/compose.yaml" "$@"
}

: "${OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD:=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
: "${OPSCUSTODIAN_INTEGRATION_API_TOKEN:=integration-$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
: "${OPSCUSTODIAN_INTEGRATION_POOL_HOLD_SECONDS:=10}"
export OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD OPSCUSTODIAN_INTEGRATION_API_TOKEN
export OPSCUSTODIAN_INTEGRATION_HEALTHCHECK_INTERVAL=2s

case "$OPSCUSTODIAN_INTEGRATION_POOL_HOLD_SECONDS" in
  ''|*[!0-9]*) echo "OPSCUSTODIAN_INTEGRATION_POOL_HOLD_SECONDS must be an integer between 8 and 12" >&2; exit 1 ;;
esac
if [ "$OPSCUSTODIAN_INTEGRATION_POOL_HOLD_SECONDS" -lt 8 ] || [ "$OPSCUSTODIAN_INTEGRATION_POOL_HOLD_SECONDS" -gt 12 ]; then
  echo "OPSCUSTODIAN_INTEGRATION_POOL_HOLD_SECONDS must be between 8 and 12" >&2
  exit 1
fi

holder_output=$(mktemp)
readiness_output=$(mktemp)
holder_pid=
readiness_pid=
pool_trigger_installed=false
cleanup() {
  if [ -n "$readiness_pid" ]; then kill "$readiness_pid" 2>/dev/null || true; fi
  if [ -n "$holder_pid" ]; then kill "$holder_pid" 2>/dev/null || true; fi
  rm -f "$holder_output" "$readiness_output"
  if [ "$pool_trigger_installed" = true ]; then
    compose exec -T postgres psql -v ON_ERROR_STOP=1 -U opscustodian -d opscustodian <<'SQL' >/dev/null 2>&1 || true
DROP TRIGGER IF EXISTS opscustodian_pool_probe_trigger ON snapshots;
DROP FUNCTION IF EXISTS opscustodian_pool_probe();
SQL
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

# Preserve normal bootstrap so the organization exists, then isolate the probe
# and recreate the application with an intentionally bounded two-slot pool.
export OPSCUSTODIAN_INTEGRATION_REPOSITORY_SET_FILE=
export OPSCUSTODIAN_INTEGRATION_DATABASE_CONNECT_TIMEOUT=2s
export OPSCUSTODIAN_INTEGRATION_DATABASE_MAX_OPEN_CONNS=2
export OPSCUSTODIAN_INTEGRATION_DATABASE_MAX_IDLE_CONNS=2
compose up --detach --force-recreate --wait opscustodian

baseline_summary=$(compose --profile performance run --rm --no-deps loadprobe \
  -duration-seconds 10 -read-workers 4 -write-workers 1 \
  -read-rps 20 -write-rps 2 -revision-prefix pool-baseline)

compose exec -T postgres psql -v ON_ERROR_STOP=1 -U opscustodian -d opscustodian \
  -v hold_seconds="$OPSCUSTODIAN_INTEGRATION_POOL_HOLD_SECONDS" <<'SQL' >/dev/null
CREATE OR REPLACE FUNCTION opscustodian_pool_probe()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.revision LIKE 'pool-holder-%' THEN
        PERFORM pg_sleep(TG_ARGV[0]::double precision);
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER opscustodian_pool_probe_trigger
BEFORE INSERT ON snapshots
FOR EACH ROW
EXECUTE FUNCTION opscustodian_pool_probe(:'hold_seconds');
SQL
pool_trigger_installed=true

compose exec -T -e OPSCUSTODIAN_TEST_API_TOKEN="$OPSCUSTODIAN_INTEGRATION_API_TOKEN" opscustodian sh -c '
  for sequence in 1 2; do
    sed "s/\"revision\": \"proposed\"/\"revision\": \"pool-holder-$sequence\"/" \
      /fixtures/scope-expansion/agentbom.after.json > "/work/pool-holder-$sequence.json"
    wget -q -O "/work/pool-holder-$sequence.out" \
      --header="Authorization: Bearer $OPSCUSTODIAN_TEST_API_TOKEN" \
      --header="Content-Type: application/json" \
      --post-file="/work/pool-holder-$sequence.json" \
      http://127.0.0.1:8080/api/v1/snapshots &
  done
  wait
' >"$holder_output" 2>&1 &
holder_pid=$!

active_pool_queries=0
active_delayed_inserts=0
attempt=0
while [ "$active_pool_queries" != "2" ] || [ "$active_delayed_inserts" -lt 1 ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -gt 40 ]; then
    echo "the two-slot application pool did not become fully occupied with a delayed snapshot insert" >&2
    cat "$holder_output" >&2
    exit 1
  fi
  pool_activity=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*), count(*) FILTER (WHERE query LIKE 'INSERT INTO snapshots%') FROM pg_stat_activity WHERE datname = 'opscustodian' AND usename = 'opscustodian' AND state = 'active' AND pid <> pg_backend_pid();")
  active_pool_queries=${pool_activity%%|*}
  active_delayed_inserts=${pool_activity#*|}
  sleep 0.25
done

(
  attempts=0
  while [ "$attempts" -lt 60 ]; do
    attempts=$((attempts + 1))
    response=
    if response=$(compose exec -T opscustodian sh -c 'wget -S -O /dev/null http://127.0.0.1:8080/readyz' 2>&1); then
      :
    fi
    if printf '%s\n' "$response" | grep -q 'HTTP/1.1 503'; then
      printf 'degraded\n'
      exit 0
    fi
    sleep 0.25
  done
  printf 'not-observed\n'
) >"$readiness_output" &
readiness_pid=$!

read_started_ns=$(date +%s%N)
compose exec -T -e OPSCUSTODIAN_TEST_API_TOKEN="$OPSCUSTODIAN_INTEGRATION_API_TOKEN" opscustodian sh -c '
  wget -q -O /dev/null \
    --header="Authorization: Bearer $OPSCUSTODIAN_TEST_API_TOKEN" \
    http://127.0.0.1:8080/api/v1/repositories
'
read_finished_ns=$(date +%s%N)
blocked_read_ms=$(((read_finished_ns - read_started_ns) / 1000000))

if ! wait "$holder_pid"; then
  cat "$holder_output" >&2
  echo "pool-holder snapshot requests failed" >&2
  exit 1
fi
holder_pid=
if ! wait "$readiness_pid"; then
  echo "readiness observer failed" >&2
  exit 1
fi
readiness_pid=
if [ "$(cat "$readiness_output")" != "degraded" ]; then
  echo "readiness did not report database pool exhaustion within the bounded observation window" >&2
  exit 1
fi

minimum_blocked_ms=$((OPSCUSTODIAN_INTEGRATION_POOL_HOLD_SECONDS * 500))
maximum_blocked_ms=15000
if [ "$blocked_read_ms" -lt "$minimum_blocked_ms" ] || [ "$blocked_read_ms" -gt "$maximum_blocked_ms" ]; then
  echo "authenticated read wait was outside the bounded pool-exhaustion window: observed_ms=$blocked_read_ms minimum_ms=$minimum_blocked_ms maximum_ms=$maximum_blocked_ms" >&2
  exit 1
fi

compose exec -T postgres psql -v ON_ERROR_STOP=1 -U opscustodian -d opscustodian <<'SQL' >/dev/null
DROP TRIGGER opscustodian_pool_probe_trigger ON snapshots;
DROP FUNCTION opscustodian_pool_probe();
SQL
pool_trigger_installed=false

attempt=0
until compose exec -T opscustodian sh -c 'wget -q -O - http://127.0.0.1:8080/readyz' | grep -q '"status":"ready"'; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    echo "readiness did not recover after the application pool was released" >&2
    exit 1
  fi
  sleep 0.25
done

recovery_summary=$(compose --profile performance run --rm --no-deps loadprobe \
  -duration-seconds 10 -read-workers 4 -write-workers 1 \
  -read-rps 20 -write-rps 2 -revision-prefix pool-recovery)

json_operation_metric() {
  operation=$1
  metric=$2
  printf '%s\n' "$3" | sed -n "s/.*\"$operation\":{[^}]*\"$metric\":\([0-9][0-9]*\).*/\1/p"
}

baseline_write_success=$(json_operation_metric write successes "$baseline_summary")
recovery_write_success=$(json_operation_metric write successes "$recovery_summary")
case "$baseline_write_success:$recovery_write_success" in
  *[!0-9:]*) echo "load probe returned invalid write counters" >&2; exit 1 ;;
  :*|*:) echo "load probe omitted write counters" >&2; exit 1 ;;
esac

baseline_snapshot_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots WHERE revision LIKE 'pool-baseline-%';")
holder_snapshot_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots WHERE revision LIKE 'pool-holder-%';")
recovery_snapshot_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots WHERE revision LIKE 'pool-recovery-%';")
orphan_findings=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshot_findings finding LEFT JOIN snapshots snapshot ON snapshot.organization_id = finding.organization_id AND snapshot.repository_id = finding.repository_id AND snapshot.id = finding.snapshot_id WHERE snapshot.id IS NULL;")
audit_identity_violations=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM audit_events WHERE event_id IS NULL OR event->>'eventId' IS DISTINCT FROM event_id;")
audit_duplicate_groups=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM (SELECT organization_id, event_id FROM audit_events GROUP BY organization_id, event_id HAVING count(*) > 1) duplicates;")
pending_spool_count=$(compose run --rm --no-deps --entrypoint sh opscustodian -c '
  set -- /audit-spool/audit-*.json
  if [ -e "$1" ]; then echo "$#"; else echo 0; fi
')

if [ "$baseline_snapshot_count" != "$baseline_write_success" ] || \
   [ "$holder_snapshot_count" != "2" ] || \
   [ "$recovery_snapshot_count" != "$recovery_write_success" ] || \
   [ "$orphan_findings" != "0" ] || \
   [ "$audit_identity_violations" != "0" ] || \
   [ "$audit_duplicate_groups" != "0" ] || \
   [ "$pending_spool_count" != "0" ]; then
  echo "pool recovery integrity verification failed: baseline_snapshots=$baseline_snapshot_count baseline_writes=$baseline_write_success holder_snapshots=$holder_snapshot_count recovery_snapshots=$recovery_snapshot_count recovery_writes=$recovery_write_success orphan_findings=$orphan_findings identity_violations=$audit_identity_violations duplicate_groups=$audit_duplicate_groups pending_spool=$pending_spool_count" >&2
  exit 1
fi

printf 'OpsCustodian pool recovery passed: max_open_connections=2 active_pool_queries=%s active_delayed_inserts=%s hold_seconds=%s blocked_read_ms=%s readiness_transition=degraded-to-ready snapshots=%s/%s/%s recovery=%s\n' \
  "$active_pool_queries" "$active_delayed_inserts" "$OPSCUSTODIAN_INTEGRATION_POOL_HOLD_SECONDS" "$blocked_read_ms" "$baseline_snapshot_count" "$holder_snapshot_count" "$recovery_snapshot_count" "$recovery_summary"

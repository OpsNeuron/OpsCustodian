#!/usr/bin/env sh
set -eu

integration_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

compose() {
  docker compose --project-directory "$integration_dir" -f "$integration_dir/compose.yaml" "$@"
}

: "${OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD:=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
: "${OPSCUSTODIAN_INTEGRATION_API_TOKEN:=integration-$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
: "${OPSCUSTODIAN_INTEGRATION_BASELINE_DURATION_SECONDS:=10}"
: "${OPSCUSTODIAN_INTEGRATION_LATENCY_DURATION_SECONDS:=15}"
: "${OPSCUSTODIAN_INTEGRATION_LATENCY_MILLISECONDS:=200}"
: "${OPSCUSTODIAN_INTEGRATION_LATENCY_RECOVERY_DURATION_SECONDS:=10}"
export OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD OPSCUSTODIAN_INTEGRATION_API_TOKEN
export OPSCUSTODIAN_INTEGRATION_HEALTHCHECK_INTERVAL=2s

require_bounded_integer() {
  name=$1
  value=$2
  minimum=$3
  maximum=$4
  case "$value" in
    ''|*[!0-9]*) echo "$name must be an integer between $minimum and $maximum" >&2; exit 1 ;;
  esac
  if [ "$value" -lt "$minimum" ] || [ "$value" -gt "$maximum" ]; then
    echo "$name must be between $minimum and $maximum" >&2
    exit 1
  fi
}

require_bounded_integer OPSCUSTODIAN_INTEGRATION_BASELINE_DURATION_SECONDS "$OPSCUSTODIAN_INTEGRATION_BASELINE_DURATION_SECONDS" 10 300
require_bounded_integer OPSCUSTODIAN_INTEGRATION_LATENCY_DURATION_SECONDS "$OPSCUSTODIAN_INTEGRATION_LATENCY_DURATION_SECONDS" 10 300
require_bounded_integer OPSCUSTODIAN_INTEGRATION_LATENCY_MILLISECONDS "$OPSCUSTODIAN_INTEGRATION_LATENCY_MILLISECONDS" 100 2000
require_bounded_integer OPSCUSTODIAN_INTEGRATION_LATENCY_RECOVERY_DURATION_SECONDS "$OPSCUSTODIAN_INTEGRATION_LATENCY_RECOVERY_DURATION_SECONDS" 10 300

latency_trigger_installed=false
cleanup() {
  if [ "$latency_trigger_installed" = true ]; then
    compose exec -T postgres psql -v ON_ERROR_STOP=1 -U opscustodian -d opscustodian <<'SQL' >/dev/null 2>&1 || true
DROP TRIGGER IF EXISTS opscustodian_latency_probe_trigger ON snapshots;
DROP FUNCTION IF EXISTS opscustodian_latency_probe();
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

# Preserve normal bootstrap so the organization exists, then remove the
# scheduled repository set to isolate this probe's authenticated writes.
export OPSCUSTODIAN_INTEGRATION_REPOSITORY_SET_FILE=
compose up --detach --force-recreate --wait opscustodian

run_probe() {
  duration=$1
  revision_prefix=$2
  compose --profile performance run --rm --no-deps loadprobe \
    -duration-seconds "$duration" \
    -read-workers 4 -write-workers 1 -read-rps 20 -write-rps 4 \
    -revision-prefix "$revision_prefix"
}

json_operation_metric() {
  operation=$1
  metric=$2
  printf '%s\n' "$3" | sed -n "s/.*\"$operation\":{[^}]*\"$metric\":\([0-9][0-9.]*\).*/\1/p"
}

require_metric() {
  name=$1
  value=$2
  case "$value" in
    ''|*[!0-9.]*) echo "$name is missing or invalid" >&2; exit 1 ;;
  esac
}

baseline_summary=$(run_probe "$OPSCUSTODIAN_INTEGRATION_BASELINE_DURATION_SECONDS" latency-baseline)

latency_seconds=$(awk -v milliseconds="$OPSCUSTODIAN_INTEGRATION_LATENCY_MILLISECONDS" 'BEGIN { printf "%.3f", milliseconds / 1000 }')
compose exec -T postgres psql -v ON_ERROR_STOP=1 -U opscustodian -d opscustodian \
  -v latency_seconds="$latency_seconds" <<'SQL' >/dev/null
CREATE OR REPLACE FUNCTION opscustodian_latency_probe()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.revision LIKE 'latency-delayed-%' THEN
        PERFORM pg_sleep(TG_ARGV[0]::double precision);
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER opscustodian_latency_probe_trigger
BEFORE INSERT ON snapshots
FOR EACH ROW
EXECUTE FUNCTION opscustodian_latency_probe(:'latency_seconds');
SQL
latency_trigger_installed=true

delayed_summary=$(run_probe "$OPSCUSTODIAN_INTEGRATION_LATENCY_DURATION_SECONDS" latency-delayed)

compose exec -T postgres psql -v ON_ERROR_STOP=1 -U opscustodian -d opscustodian <<'SQL' >/dev/null
DROP TRIGGER opscustodian_latency_probe_trigger ON snapshots;
DROP FUNCTION opscustodian_latency_probe();
SQL
latency_trigger_installed=false

recovery_summary=$(run_probe "$OPSCUSTODIAN_INTEGRATION_LATENCY_RECOVERY_DURATION_SECONDS" latency-recovery)

baseline_write_success=$(json_operation_metric write successes "$baseline_summary")
delayed_write_success=$(json_operation_metric write successes "$delayed_summary")
recovery_write_success=$(json_operation_metric write successes "$recovery_summary")
baseline_write_p50=$(json_operation_metric write latencyP50Ms "$baseline_summary")
delayed_write_p50=$(json_operation_metric write latencyP50Ms "$delayed_summary")
delayed_write_p99=$(json_operation_metric write latencyP99Ms "$delayed_summary")
recovery_write_p50=$(json_operation_metric write latencyP50Ms "$recovery_summary")
delayed_read_p99=$(json_operation_metric read latencyP99Ms "$delayed_summary")
delayed_readiness_max=$(json_operation_metric readiness latencyMaxMs "$delayed_summary")

for metric in \
  "baseline_write_success:$baseline_write_success" \
  "delayed_write_success:$delayed_write_success" \
  "recovery_write_success:$recovery_write_success" \
  "baseline_write_p50:$baseline_write_p50" \
  "delayed_write_p50:$delayed_write_p50" \
  "delayed_write_p99:$delayed_write_p99" \
  "recovery_write_p50:$recovery_write_p50" \
  "delayed_read_p99:$delayed_read_p99" \
  "delayed_readiness_max:$delayed_readiness_max"; do
  require_metric "${metric%%:*}" "${metric#*:}"
done

minimum_increase=$((OPSCUSTODIAN_INTEGRATION_LATENCY_MILLISECONDS * 3 / 4))
minimum_recovery=$((OPSCUSTODIAN_INTEGRATION_LATENCY_MILLISECONDS / 2))
maximum_delayed_p99=$((OPSCUSTODIAN_INTEGRATION_LATENCY_MILLISECONDS + 1500))
if ! awk -v baseline="$baseline_write_p50" -v delayed="$delayed_write_p50" -v increase="$minimum_increase" \
  'BEGIN { exit !(delayed >= baseline + increase) }'; then
  echo "write latency did not increase by the required bounded margin: baseline_p50_ms=$baseline_write_p50 delayed_p50_ms=$delayed_write_p50 required_increase_ms=$minimum_increase" >&2
  exit 1
fi
if ! awk -v delayed="$delayed_write_p50" -v recovery="$recovery_write_p50" -v decrease="$minimum_recovery" \
  'BEGIN { exit !(recovery <= delayed - decrease) }'; then
  echo "write latency did not recover by the required margin: delayed_p50_ms=$delayed_write_p50 recovery_p50_ms=$recovery_write_p50 required_decrease_ms=$minimum_recovery" >&2
  exit 1
fi
if ! awk -v delayed="$delayed_write_p99" -v maximum="$maximum_delayed_p99" \
  'BEGIN { exit !(delayed <= maximum) }'; then
  echo "delayed write p99 exceeded the bounded ceiling: delayed_p99_ms=$delayed_write_p99 maximum_ms=$maximum_delayed_p99" >&2
  exit 1
fi

baseline_snapshot_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots WHERE revision LIKE 'latency-baseline-%';")
delayed_snapshot_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots WHERE revision LIKE 'latency-delayed-%';")
recovery_snapshot_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots WHERE revision LIKE 'latency-recovery-%';")
orphan_findings=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshot_findings finding LEFT JOIN snapshots snapshot ON snapshot.organization_id = finding.organization_id AND snapshot.repository_id = finding.repository_id AND snapshot.id = finding.snapshot_id WHERE snapshot.id IS NULL;")
audit_identity_violations=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM audit_events WHERE event_id IS NULL OR event->>'eventId' IS DISTINCT FROM event_id;")
audit_duplicate_groups=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM (SELECT organization_id, event_id FROM audit_events GROUP BY organization_id, event_id HAVING count(*) > 1) duplicates;")
pending_spool_count=$(compose run --rm --no-deps --entrypoint sh opscustodian -c '
  set -- /audit-spool/audit-*.json
  if [ -e "$1" ]; then echo "$#"; else echo 0; fi
')

if [ "$baseline_snapshot_count" != "$baseline_write_success" ] || \
   [ "$delayed_snapshot_count" != "$delayed_write_success" ] || \
   [ "$recovery_snapshot_count" != "$recovery_write_success" ] || \
   [ "$orphan_findings" != "0" ] || \
   [ "$audit_identity_violations" != "0" ] || \
   [ "$audit_duplicate_groups" != "0" ] || \
   [ "$pending_spool_count" != "0" ]; then
  echo "latency recovery integrity verification failed: baseline_snapshots=$baseline_snapshot_count baseline_writes=$baseline_write_success delayed_snapshots=$delayed_snapshot_count delayed_writes=$delayed_write_success recovery_snapshots=$recovery_snapshot_count recovery_writes=$recovery_write_success orphan_findings=$orphan_findings identity_violations=$audit_identity_violations duplicate_groups=$audit_duplicate_groups pending_spool=$pending_spool_count" >&2
  exit 1
fi

printf 'OpsCustodian latency recovery passed: injected_ms=%s baseline_write_p50_ms=%s delayed_write_p50_ms=%s delayed_write_p99_ms=%s recovery_write_p50_ms=%s delayed_read_p99_ms=%s delayed_readiness_max_ms=%s snapshots=%s/%s/%s\n' \
  "$OPSCUSTODIAN_INTEGRATION_LATENCY_MILLISECONDS" "$baseline_write_p50" "$delayed_write_p50" "$delayed_write_p99" "$recovery_write_p50" "$delayed_read_p99" "$delayed_readiness_max" "$baseline_snapshot_count" "$delayed_snapshot_count" "$recovery_snapshot_count"

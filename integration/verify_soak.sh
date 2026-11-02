#!/usr/bin/env sh
set -eu

integration_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

compose() {
  docker compose --project-directory "$integration_dir" -f "$integration_dir/compose.yaml" "$@"
}

: "${OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD:=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
: "${OPSCUSTODIAN_INTEGRATION_API_TOKEN:=integration-$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
: "${OPSCUSTODIAN_INTEGRATION_SOAK_DURATION_SECONDS:=300}"
: "${OPSCUSTODIAN_INTEGRATION_SOAK_READ_WORKERS:=16}"
: "${OPSCUSTODIAN_INTEGRATION_SOAK_WRITE_WORKERS:=4}"
: "${OPSCUSTODIAN_INTEGRATION_SOAK_READ_RPS:=100}"
: "${OPSCUSTODIAN_INTEGRATION_SOAK_WRITE_RPS:=10}"
: "${OPSCUSTODIAN_INTEGRATION_SOAK_SAMPLE_SECONDS:=5}"
export OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD OPSCUSTODIAN_INTEGRATION_API_TOKEN

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

require_bounded_integer OPSCUSTODIAN_INTEGRATION_SOAK_DURATION_SECONDS "$OPSCUSTODIAN_INTEGRATION_SOAK_DURATION_SECONDS" 10 14400
require_bounded_integer OPSCUSTODIAN_INTEGRATION_SOAK_READ_WORKERS "$OPSCUSTODIAN_INTEGRATION_SOAK_READ_WORKERS" 1 64
require_bounded_integer OPSCUSTODIAN_INTEGRATION_SOAK_WRITE_WORKERS "$OPSCUSTODIAN_INTEGRATION_SOAK_WRITE_WORKERS" 1 16
require_bounded_integer OPSCUSTODIAN_INTEGRATION_SOAK_READ_RPS "$OPSCUSTODIAN_INTEGRATION_SOAK_READ_RPS" 1 5000
require_bounded_integer OPSCUSTODIAN_INTEGRATION_SOAK_WRITE_RPS "$OPSCUSTODIAN_INTEGRATION_SOAK_WRITE_RPS" 1 1000
require_bounded_integer OPSCUSTODIAN_INTEGRATION_SOAK_SAMPLE_SECONDS "$OPSCUSTODIAN_INTEGRATION_SOAK_SAMPLE_SECONDS" 1 60
if [ $((OPSCUSTODIAN_INTEGRATION_SOAK_READ_WORKERS + OPSCUSTODIAN_INTEGRATION_SOAK_WRITE_WORKERS)) -gt 64 ]; then
  echo "combined soak concurrency must not exceed 64" >&2
  exit 1
fi

summary_file=$(mktemp)
stats_file=$(mktemp)
cleanup() {
  rm -f "$summary_file" "$stats_file"
  if [ "${OPSCUSTODIAN_INTEGRATION_KEEP:-false}" != "true" ]; then
    compose --profile performance down --volumes --remove-orphans
  fi
}
trap cleanup EXIT INT TERM

compose --profile performance build opscustodian loadprobe
compose run --rm --no-deps --entrypoint sh opscustodian -c 'chmod 700 /audit-spool'
compose up --detach --wait postgres collector opscustodian

compose --profile performance run --rm --no-deps loadprobe \
  -duration-seconds "$OPSCUSTODIAN_INTEGRATION_SOAK_DURATION_SECONDS" \
  -read-workers "$OPSCUSTODIAN_INTEGRATION_SOAK_READ_WORKERS" \
  -write-workers "$OPSCUSTODIAN_INTEGRATION_SOAK_WRITE_WORKERS" \
  -read-rps "$OPSCUSTODIAN_INTEGRATION_SOAK_READ_RPS" \
  -write-rps "$OPSCUSTODIAN_INTEGRATION_SOAK_WRITE_RPS" \
  -revision-prefix soak > "$summary_file" &
probe_pid=$!

while kill -0 "$probe_pid" 2>/dev/null; do
  for service in opscustodian postgres collector; do
    container_id=$(compose ps -q "$service")
    if [ -n "$container_id" ]; then
      docker stats --no-stream --format "$service|{{.CPUPerc}}|{{.MemPerc}}|{{.PIDs}}" "$container_id" >> "$stats_file" 2>/dev/null || true
    fi
  done
  sleep "$OPSCUSTODIAN_INTEGRATION_SOAK_SAMPLE_SECONDS"
done
if ! wait "$probe_pid"; then
  cat "$summary_file" >&2
  compose logs opscustodian postgres >&2
  exit 1
fi

summary=$(cat "$summary_file")
json_integer() {
  key=$1
  printf '%s\n' "$summary" | sed -n "s/.*\"$key\":\([0-9][0-9]*\).*/\1/p" | head -n 1
}
read_success=$(printf '%s\n' "$summary" | sed -n 's/.*"read":{\"successes\":\([0-9][0-9]*\).*/\1/p')
write_success=$(printf '%s\n' "$summary" | sed -n 's/.*"write":{\"successes\":\([0-9][0-9]*\).*/\1/p')
if [ -z "$read_success" ] || [ -z "$write_success" ]; then
  echo "soak probe returned an invalid summary: $summary" >&2
  exit 1
fi

snapshot_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots WHERE revision LIKE 'soak-%';")
orphan_findings=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshot_findings finding LEFT JOIN snapshots snapshot ON snapshot.organization_id = finding.organization_id AND snapshot.repository_id = finding.repository_id AND snapshot.id = finding.snapshot_id WHERE snapshot.id IS NULL;")
audit_identity_violations=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM audit_events WHERE event_id IS NULL OR event->>'eventId' IS DISTINCT FROM event_id;")
audit_duplicate_groups=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM (SELECT organization_id, event_id FROM audit_events GROUP BY organization_id, event_id HAVING count(*) > 1) duplicates;")
pending_spool_count=$(compose run --rm --no-deps --entrypoint sh opscustodian -c '
  set -- /audit-spool/audit-*.json
  if [ -e "$1" ]; then echo "$#"; else echo 0; fi
')
if [ "$snapshot_count" != "$write_success" ] || [ "$orphan_findings" != "0" ] || [ "$audit_identity_violations" != "0" ] || [ "$audit_duplicate_groups" != "0" ] || [ "$pending_spool_count" != "0" ]; then
  echo "soak integrity verification failed: snapshots=$snapshot_count writes=$write_success orphan_findings=$orphan_findings identity_violations=$audit_identity_violations duplicate_groups=$audit_duplicate_groups pending_spool=$pending_spool_count" >&2
  exit 1
fi

if ! wget_output=$(compose exec -T opscustodian wget -q -O - http://127.0.0.1:8080/readyz) || ! printf '%s' "$wget_output" | grep -q '"status":"ready"'; then
  echo "control plane was not ready after the soak probe" >&2
  exit 1
fi

resource_summary() {
  service=$1
  awk -F'|' -v service="$service" '
    $1 == service {
      cpu=$2; memory=$3; gsub(/%/, "", cpu); gsub(/%/, "", memory)
      if (cpu + 0 > max_cpu) max_cpu=cpu + 0
      if (memory + 0 > max_memory) max_memory=memory + 0
      if ($4 + 0 > max_pids) max_pids=$4 + 0
      samples++
    }
    END {
      if (samples == 0) exit 1
      printf "%s_samples=%d %s_peak_cpu_percent=%.2f %s_peak_memory_percent=%.2f %s_peak_pids=%d", service, samples, service, max_cpu, service, max_memory, service, max_pids
    }
  ' "$stats_file"
}

app_resources=$(resource_summary opscustodian)
postgres_resources=$(resource_summary postgres)
collector_resources=$(resource_summary collector)
printf 'OpsCustodian soak probe passed: %s snapshots=%s %s %s %s\n' "$summary" "$snapshot_count" "$app_resources" "$postgres_resources" "$collector_resources"

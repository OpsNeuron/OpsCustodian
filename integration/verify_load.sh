#!/usr/bin/env sh
set -eu

integration_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

compose() {
  docker compose --project-directory "$integration_dir" -f "$integration_dir/compose.yaml" "$@"
}

: "${OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD:=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
: "${OPSCUSTODIAN_INTEGRATION_API_TOKEN:=integration-$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
: "${OPSCUSTODIAN_INTEGRATION_LOAD_DURATION_SECONDS:=30}"
: "${OPSCUSTODIAN_INTEGRATION_LOAD_READ_WORKERS:=8}"
: "${OPSCUSTODIAN_INTEGRATION_LOAD_WRITE_WORKERS:=2}"
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

require_bounded_integer OPSCUSTODIAN_INTEGRATION_LOAD_DURATION_SECONDS "$OPSCUSTODIAN_INTEGRATION_LOAD_DURATION_SECONDS" 10 3600
require_bounded_integer OPSCUSTODIAN_INTEGRATION_LOAD_READ_WORKERS "$OPSCUSTODIAN_INTEGRATION_LOAD_READ_WORKERS" 1 64
require_bounded_integer OPSCUSTODIAN_INTEGRATION_LOAD_WRITE_WORKERS "$OPSCUSTODIAN_INTEGRATION_LOAD_WRITE_WORKERS" 1 16
if [ $((OPSCUSTODIAN_INTEGRATION_LOAD_READ_WORKERS + OPSCUSTODIAN_INTEGRATION_LOAD_WRITE_WORKERS)) -gt 64 ]; then
  echo "combined load concurrency must not exceed 64" >&2
  exit 1
fi

cleanup() {
  if [ "${OPSCUSTODIAN_INTEGRATION_KEEP:-false}" != "true" ]; then
    compose down --volumes --remove-orphans
  fi
}
trap cleanup EXIT INT TERM

compose build opscustodian
compose run --rm --no-deps --entrypoint sh opscustodian -c 'chmod 700 /audit-spool'
compose up --detach --wait postgres collector opscustodian

load_summary=$(compose exec -T \
  -e OPSCUSTODIAN_TEST_API_TOKEN="$OPSCUSTODIAN_INTEGRATION_API_TOKEN" \
  -e LOAD_DURATION_SECONDS="$OPSCUSTODIAN_INTEGRATION_LOAD_DURATION_SECONDS" \
  -e LOAD_READ_WORKERS="$OPSCUSTODIAN_INTEGRATION_LOAD_READ_WORKERS" \
  -e LOAD_WRITE_WORKERS="$OPSCUSTODIAN_INTEGRATION_LOAD_WRITE_WORKERS" \
  opscustodian sh -c '
set -eu
result_dir=/tmp/opscustodian-load-results
rm -rf "$result_dir"
mkdir -p "$result_dir"
deadline=$(( $(date +%s) + LOAD_DURATION_SECONDS ))

read_worker() {
  worker=$1
  successes=0
  errors=0
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if wget -q -O /dev/null --header="Authorization: Bearer $OPSCUSTODIAN_TEST_API_TOKEN" http://127.0.0.1:8080/api/v1/repositories; then
      successes=$((successes + 1))
    else
      errors=$((errors + 1))
    fi
  done
  printf "%s %s\n" "$successes" "$errors" > "$result_dir/read-$worker"
}

write_worker() {
  worker=$1
  sequence=0
  successes=0
  errors=0
  fixture="$result_dir/write-$worker.json"
  while [ "$(date +%s)" -lt "$deadline" ]; do
    sequence=$((sequence + 1))
    revision="load-${worker}-${sequence}"
    sed "s/\"revision\": \"proposed\"/\"revision\": \"$revision\"/" /fixtures/scope-expansion/agentbom.after.json > "$fixture"
    if wget -q -O /dev/null --header="Authorization: Bearer $OPSCUSTODIAN_TEST_API_TOKEN" --header="Content-Type: application/json" --post-file="$fixture" http://127.0.0.1:8080/api/v1/snapshots; then
      successes=$((successes + 1))
    else
      errors=$((errors + 1))
    fi
  done
  rm -f "$fixture"
  printf "%s %s\n" "$successes" "$errors" > "$result_dir/write-$worker"
}

health_worker() {
  successes=0
  errors=0
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if wget -q -O - http://127.0.0.1:8080/readyz | grep -q "\"status\":\"ready\""; then
      successes=$((successes + 1))
    else
      errors=$((errors + 1))
    fi
    sleep 1
  done
  printf "%s %s\n" "$successes" "$errors" > "$result_dir/health"
}

worker=1
while [ "$worker" -le "$LOAD_READ_WORKERS" ]; do
  read_worker "$worker" &
  worker=$((worker + 1))
done
worker=1
while [ "$worker" -le "$LOAD_WRITE_WORKERS" ]; do
  write_worker "$worker" &
  worker=$((worker + 1))
done
health_worker &
wait

read_success=$(awk "{ total += \$1 } END { print total + 0 }" "$result_dir"/read-*)
read_errors=$(awk "{ total += \$2 } END { print total + 0 }" "$result_dir"/read-*)
write_success=$(awk "{ total += \$1 } END { print total + 0 }" "$result_dir"/write-*)
write_errors=$(awk "{ total += \$2 } END { print total + 0 }" "$result_dir"/write-*)
health_success=$(awk "{ total += \$1 } END { print total + 0 }" "$result_dir"/health)
health_errors=$(awk "{ total += \$2 } END { print total + 0 }" "$result_dir"/health)
rm -rf "$result_dir"
printf "read_success=%s read_errors=%s write_success=%s write_errors=%s health_success=%s health_errors=%s\n" "$read_success" "$read_errors" "$write_success" "$write_errors" "$health_success" "$health_errors"
')

metric() {
  key=$1
  printf '%s\n' "$load_summary" | tr ' ' '\n' | sed -n "s/^$key=//p"
}

read_success=$(metric read_success)
read_errors=$(metric read_errors)
write_success=$(metric write_success)
write_errors=$(metric write_errors)
health_success=$(metric health_success)
health_errors=$(metric health_errors)
for value in "$read_success" "$read_errors" "$write_success" "$write_errors" "$health_success" "$health_errors"; do
  case "$value" in ''|*[!0-9]*) echo "load harness returned invalid counters" >&2; exit 1 ;; esac
done
if [ "$read_success" -lt "$OPSCUSTODIAN_INTEGRATION_LOAD_READ_WORKERS" ] || [ "$write_success" -lt "$OPSCUSTODIAN_INTEGRATION_LOAD_WRITE_WORKERS" ] || [ "$health_success" -lt 1 ] || [ "$read_errors" -ne 0 ] || [ "$write_errors" -ne 0 ] || [ "$health_errors" -ne 0 ]; then
  echo "load smoke failed: $load_summary" >&2
  compose logs opscustodian >&2
  exit 1
fi

load_snapshot_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots WHERE revision LIKE 'load-%';")
audit_identity_violations=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM audit_events WHERE event_id IS NULL OR event->>'eventId' IS DISTINCT FROM event_id;")
audit_duplicate_groups=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM (SELECT organization_id, event_id FROM audit_events GROUP BY organization_id, event_id HAVING count(*) > 1) duplicates;")
pending_spool_count=$(compose run --rm --no-deps --entrypoint sh opscustodian -c '
  set -- /audit-spool/audit-*.json
  if [ -e "$1" ]; then echo "$#"; else echo 0; fi
')
if [ "$load_snapshot_count" != "$write_success" ] || [ "$audit_identity_violations" != "0" ] || [ "$audit_duplicate_groups" != "0" ] || [ "$pending_spool_count" != "0" ]; then
  echo "load integrity verification failed: snapshots=$load_snapshot_count writes=$write_success identity_violations=$audit_identity_violations duplicate_groups=$audit_duplicate_groups pending_spool=$pending_spool_count" >&2
  exit 1
fi

total_success=$((read_success + write_success + health_success))
throughput=$((total_success / OPSCUSTODIAN_INTEGRATION_LOAD_DURATION_SECONDS))
printf 'OpsCustodian load smoke passed: duration=%ss read_workers=%s write_workers=%s read_success=%s write_success=%s health_checks=%s approximate_requests_per_second=%s\n' \
  "$OPSCUSTODIAN_INTEGRATION_LOAD_DURATION_SECONDS" \
  "$OPSCUSTODIAN_INTEGRATION_LOAD_READ_WORKERS" \
  "$OPSCUSTODIAN_INTEGRATION_LOAD_WRITE_WORKERS" \
  "$read_success" "$write_success" "$health_success" "$throughput"

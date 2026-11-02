#!/usr/bin/env sh
set -eu

integration_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

compose() {
  docker compose --project-directory "$integration_dir" -f "$integration_dir/compose.yaml" "$@"
}

: "${OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD:=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
: "${OPSCUSTODIAN_INTEGRATION_API_TOKEN:=integration-$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
: "${OPSCUSTODIAN_INTEGRATION_FAILURE_DURATION_SECONDS:=30}"
: "${OPSCUSTODIAN_INTEGRATION_FAILURE_AFTER_SECONDS:=10}"
: "${OPSCUSTODIAN_INTEGRATION_RECOVERY_DURATION_SECONDS:=20}"
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

require_bounded_integer OPSCUSTODIAN_INTEGRATION_FAILURE_DURATION_SECONDS "$OPSCUSTODIAN_INTEGRATION_FAILURE_DURATION_SECONDS" 15 300
require_bounded_integer OPSCUSTODIAN_INTEGRATION_FAILURE_AFTER_SECONDS "$OPSCUSTODIAN_INTEGRATION_FAILURE_AFTER_SECONDS" 5 120
require_bounded_integer OPSCUSTODIAN_INTEGRATION_RECOVERY_DURATION_SECONDS "$OPSCUSTODIAN_INTEGRATION_RECOVERY_DURATION_SECONDS" 10 300
if [ "$OPSCUSTODIAN_INTEGRATION_FAILURE_AFTER_SECONDS" -ge "$OPSCUSTODIAN_INTEGRATION_FAILURE_DURATION_SECONDS" ]; then
  echo "failure injection must occur before the failure probe ends" >&2
  exit 1
fi

failure_summary_file=$(mktemp)
cleanup() {
  rm -f "$failure_summary_file"
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
export OPSCUSTODIAN_INTEGRATION_REPOSITORY_SET_FILE=
compose up --detach --force-recreate --wait opscustodian

compose --profile performance run --rm --no-deps loadprobe \
  -duration-seconds "$OPSCUSTODIAN_INTEGRATION_FAILURE_DURATION_SECONDS" \
  -read-workers 4 -write-workers 1 -read-rps 20 -write-rps 2 \
  -revision-prefix failure-pre -expect-failures > "$failure_summary_file" &
probe_pid=$!

sleep "$OPSCUSTODIAN_INTEGRATION_FAILURE_AFTER_SECONDS"
compose stop postgres

attempt=0
while compose ps --status running --services | grep -qx 'opscustodian'; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "control plane did not fail closed under database outage load" >&2
    compose logs opscustodian >&2
    exit 1
  fi
  sleep 1
done

if ! wait "$probe_pid"; then
  cat "$failure_summary_file" >&2
  compose logs opscustodian postgres >&2
  exit 1
fi
failure_summary=$(cat "$failure_summary_file")

json_operation_metric() {
  operation=$1
  metric=$2
  printf '%s\n' "$3" | sed -n "s/.*\"$operation\":{[^}]*\"$metric\":\([0-9][0-9]*\).*/\1/p"
}

pre_read_success=$(json_operation_metric read successes "$failure_summary")
pre_read_errors=$(json_operation_metric read errors "$failure_summary")
pre_write_success=$(json_operation_metric write successes "$failure_summary")
pre_write_errors=$(json_operation_metric write errors "$failure_summary")
pre_readiness_errors=$(json_operation_metric readiness errors "$failure_summary")
for value in "$pre_read_success" "$pre_read_errors" "$pre_write_success" "$pre_write_errors" "$pre_readiness_errors"; do
  case "$value" in ''|*[!0-9]*) echo "failure probe returned invalid counters: $failure_summary" >&2; exit 1 ;; esac
done
if [ "$pre_read_errors" -eq 0 ] || [ "$pre_write_errors" -eq 0 ] || [ "$pre_readiness_errors" -eq 0 ]; then
  echo "failure probe did not observe all expected failure classes: $failure_summary" >&2
  exit 1
fi

spooled_event_ids=$(compose run --rm --no-deps --entrypoint sh opscustodian -c '
  found=false
  for path in /audit-spool/audit-*.json; do
    if [ -f "$path" ]; then
      found=true
      basename "$path" .json
    fi
  done
  if [ "$found" = false ]; then exit 1; fi
')
spooled_event_count=0
for event_id in $spooled_event_ids; do
  if ! printf '%s\n' "$event_id" | grep -Eq '^audit-[0-9a-f]{32}$'; then
    echo "durable audit event ID is invalid" >&2
    exit 1
  fi
  spooled_event_count=$((spooled_event_count + 1))
done
if [ "$spooled_event_count" -lt 1 ] || [ "$spooled_event_count" -gt 100 ]; then
  echo "unexpected durable audit event count: $spooled_event_count" >&2
  exit 1
fi

compose start postgres
compose up --detach --force-recreate --wait opscustodian

for event_id in $spooled_event_ids; do
  replayed_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM audit_events WHERE event_id = '$event_id';")
  if [ "$replayed_count" != "1" ]; then
    echo "durable event $event_id was not replayed exactly once" >&2
    exit 1
  fi
done
pending_spool_count=$(compose run --rm --no-deps --entrypoint sh opscustodian -c '
  set -- /audit-spool/audit-*.json
  if [ -e "$1" ]; then echo "$#"; else echo 0; fi
')
if [ "$pending_spool_count" != "0" ]; then
  echo "durable spool was not empty after recovery: $pending_spool_count" >&2
  exit 1
fi

recovery_summary=$(compose --profile performance run --rm --no-deps loadprobe \
  -duration-seconds "$OPSCUSTODIAN_INTEGRATION_RECOVERY_DURATION_SECONDS" \
  -read-workers 4 -write-workers 1 -read-rps 20 -write-rps 2 \
  -revision-prefix failure-post)
post_write_success=$(json_operation_metric write successes "$recovery_summary")
case "$post_write_success" in ''|*[!0-9]*) echo "recovery probe returned invalid counters: $recovery_summary" >&2; exit 1 ;; esac

pre_snapshot_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots WHERE revision LIKE 'failure-pre-%';")
post_snapshot_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots WHERE revision LIKE 'failure-post-%';")
pre_write_attempts=$((pre_write_success + pre_write_errors))
orphan_findings=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshot_findings finding LEFT JOIN snapshots snapshot ON snapshot.organization_id = finding.organization_id AND snapshot.repository_id = finding.repository_id AND snapshot.id = finding.snapshot_id WHERE snapshot.id IS NULL;")
audit_identity_violations=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM audit_events WHERE event_id IS NULL OR event->>'eventId' IS DISTINCT FROM event_id;")
audit_duplicate_groups=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM (SELECT organization_id, event_id FROM audit_events GROUP BY organization_id, event_id HAVING count(*) > 1) duplicates;")
if [ "$pre_snapshot_count" -lt "$pre_write_success" ] || [ "$pre_snapshot_count" -gt "$pre_write_attempts" ] || [ "$post_snapshot_count" != "$post_write_success" ] || [ "$orphan_findings" != "0" ] || [ "$audit_identity_violations" != "0" ] || [ "$audit_duplicate_groups" != "0" ]; then
  echo "failure recovery integrity verification failed: pre_snapshots=$pre_snapshot_count pre_success=$pre_write_success pre_attempts=$pre_write_attempts post_snapshots=$post_snapshot_count post_success=$post_write_success orphan_findings=$orphan_findings identity_violations=$audit_identity_violations duplicate_groups=$audit_duplicate_groups" >&2
  exit 1
fi

compose restart opscustodian
compose up --detach --wait opscustodian
for event_id in $spooled_event_ids; do
  restart_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM audit_events WHERE event_id = '$event_id';")
  if [ "$restart_count" != "1" ]; then
    echo "durable event $event_id was duplicated after restart" >&2
    exit 1
  fi
done

printf 'OpsCustodian failure recovery passed: pre_read_success=%s pre_read_errors=%s pre_write_success=%s pre_write_errors=%s spooled_events=%s pre_snapshots=%s post_snapshots=%s recovery=%s\n' \
  "$pre_read_success" "$pre_read_errors" "$pre_write_success" "$pre_write_errors" "$spooled_event_count" "$pre_snapshot_count" "$post_snapshot_count" "$recovery_summary"

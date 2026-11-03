#!/usr/bin/env sh
set -eu

integration_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

compose() {
  docker compose --project-directory "$integration_dir" -f "$integration_dir/compose.yaml" "$@"
}

: "${OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD:=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
: "${OPSCUSTODIAN_INTEGRATION_API_TOKEN:=integration-$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
export OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD OPSCUSTODIAN_INTEGRATION_API_TOKEN

profile_duration_seconds=120
recovery_duration_seconds=60
sample_seconds=5
minimum_attainment_percent=95
maximum_p99_ms=1000

temporary_files=""

cleanup() {
  for file in $temporary_files; do
    rm -f "$file"
  done
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

docker_environment=$(docker info --format '{{.NCPU}}|{{.MemTotal}}|{{.ServerVersion}}|{{.OperatingSystem}}|{{.OSType}}|{{.Architecture}}')
printf 'capacity_environment docker_cpus=%s docker_memory_bytes=%s docker_server_version=%s docker_operating_system="%s" docker_os_type=%s docker_architecture=%s profile_duration_seconds=%s minimum_attainment_percent=%s maximum_p99_ms=%s\n' \
  "$(printf '%s\n' "$docker_environment" | cut -d'|' -f1)" \
  "$(printf '%s\n' "$docker_environment" | cut -d'|' -f2)" \
  "$(printf '%s\n' "$docker_environment" | cut -d'|' -f3)" \
  "$(printf '%s\n' "$docker_environment" | cut -d'|' -f4)" \
  "$(printf '%s\n' "$docker_environment" | cut -d'|' -f5)" \
  "$(printf '%s\n' "$docker_environment" | cut -d'|' -f6)" \
  "$profile_duration_seconds" "$minimum_attainment_percent" "$maximum_p99_ms"

metric() {
  document=$1
  section=$2
  field=$3
  printf '%s\n' "$document" | sed -n "s/.*\"$section\":{[^}]*\"$field\":\([0-9.][0-9.]*\).*/\1/p" | head -n 1
}

top_level_metric() {
  document=$1
  field=$2
  printf '%s\n' "$document" | sed -n "s/.*\"$field\":\([0-9.][0-9.]*\).*/\1/p" | head -n 1
}

float_less_than() {
  awk -v left="$1" -v right="$2" 'BEGIN { exit !(left + 0 < right + 0) }'
}

float_greater_than() {
  awk -v left="$1" -v right="$2" 'BEGIN { exit !(left + 0 > right + 0) }'
}

resource_summary() {
  stats_file=$1
  service=$2
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

verify_integrity() {
  revision_prefix=$1
  expected_snapshots=$2
  snapshot_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots WHERE revision LIKE '${revision_prefix}-%';")
  orphan_findings=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshot_findings finding LEFT JOIN snapshots snapshot ON snapshot.organization_id = finding.organization_id AND snapshot.repository_id = finding.repository_id AND snapshot.id = finding.snapshot_id WHERE snapshot.id IS NULL;")
  audit_identity_violations=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM audit_events WHERE event_id IS NULL OR event->>'eventId' IS DISTINCT FROM event_id;")
  audit_duplicate_groups=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM (SELECT organization_id, event_id FROM audit_events GROUP BY organization_id, event_id HAVING count(*) > 1) duplicates;")
  pending_spool_count=$(compose run --rm --no-deps --entrypoint sh opscustodian -c '
    set -- /audit-spool/audit-*.json
    if [ -e "$1" ]; then echo "$#"; else echo 0; fi
  ')
  if [ "$snapshot_count" != "$expected_snapshots" ] || [ "$orphan_findings" != "0" ] || [ "$audit_identity_violations" != "0" ] || [ "$audit_duplicate_groups" != "0" ] || [ "$pending_spool_count" != "0" ]; then
    echo "capacity integrity verification failed: prefix=$revision_prefix snapshots=$snapshot_count expected=$expected_snapshots orphan_findings=$orphan_findings identity_violations=$audit_identity_violations duplicate_groups=$audit_duplicate_groups pending_spool=$pending_spool_count" >&2
    return 1
  fi
  printf 'snapshots=%s orphan_findings=%s audit_identity_violations=%s audit_duplicate_groups=%s pending_spool=%s' \
    "$snapshot_count" "$orphan_findings" "$audit_identity_violations" "$audit_duplicate_groups" "$pending_spool_count"
}

run_profile() {
  profile_name=$1
  duration_seconds=$2
  read_workers=$3
  write_workers=$4
  read_rps=$5
  write_rps=$6
  summary_file=$(mktemp)
  stats_file=$(mktemp)
  temporary_files="$temporary_files $summary_file $stats_file"

  compose --profile performance run --rm --no-deps loadprobe \
    -duration-seconds "$duration_seconds" \
    -read-workers "$read_workers" \
    -write-workers "$write_workers" \
    -read-rps "$read_rps" \
    -write-rps "$write_rps" \
    -revision-prefix "$profile_name" > "$summary_file" &
  probe_pid=$!

  while kill -0 "$probe_pid" 2>/dev/null; do
    for service in opscustodian postgres collector; do
      container_id=$(compose ps -q "$service")
      if [ -n "$container_id" ]; then
        docker stats --no-stream --format "$service|{{.CPUPerc}}|{{.MemPerc}}|{{.PIDs}}" "$container_id" >> "$stats_file" 2>/dev/null || true
      fi
    done
    sleep "$sample_seconds"
  done
  if wait "$probe_pid"; then
    probe_exit=0
  else
    probe_exit=$?
  fi

  summary=$(cat "$summary_file")
  read_success=$(metric "$summary" read successes)
  read_errors=$(metric "$summary" read errors)
  read_p99=$(metric "$summary" read latencyP99Ms)
  write_success=$(metric "$summary" write successes)
  write_errors=$(metric "$summary" write errors)
  write_p99=$(metric "$summary" write latencyP99Ms)
  readiness_errors=$(metric "$summary" readiness errors)
  readiness_p99=$(metric "$summary" readiness latencyP99Ms)
  achieved_rps=$(top_level_metric "$summary" requestsPerSecond)
  if [ -z "$read_success" ] || [ -z "$read_errors" ] || [ -z "$read_p99" ] || [ -z "$write_success" ] || [ -z "$write_errors" ] || [ -z "$write_p99" ] || [ -z "$readiness_errors" ] || [ -z "$readiness_p99" ] || [ -z "$achieved_rps" ]; then
    echo "capacity profile returned an invalid summary: profile=$profile_name summary=$summary" >&2
    return 1
  fi

  target_rps=$((read_rps + write_rps))
  attainment_percent=$(awk -v achieved="$achieved_rps" -v target="$target_rps" 'BEGIN { printf "%.3f", achieved * 100 / target }')
  integrity=$(verify_integrity "$profile_name" "$write_success")
  app_resources=$(resource_summary "$stats_file" opscustodian)
  postgres_resources=$(resource_summary "$stats_file" postgres)
  collector_resources=$(resource_summary "$stats_file" collector)

  reasons=""
  if [ "$probe_exit" -ne 0 ]; then reasons="${reasons}probe_exit,"; fi
  if [ "$read_errors" != "0" ]; then reasons="${reasons}read_errors,"; fi
  if [ "$write_errors" != "0" ]; then reasons="${reasons}write_errors,"; fi
  if [ "$readiness_errors" != "0" ]; then reasons="${reasons}readiness_errors,"; fi
  if float_less_than "$attainment_percent" "$minimum_attainment_percent"; then reasons="${reasons}target_attainment,"; fi
  if float_greater_than "$read_p99" "$maximum_p99_ms"; then reasons="${reasons}read_p99,"; fi
  if float_greater_than "$write_p99" "$maximum_p99_ms"; then reasons="${reasons}write_p99,"; fi
  if float_greater_than "$readiness_p99" "$maximum_p99_ms"; then reasons="${reasons}readiness_p99,"; fi

  result=pass
  if [ -n "$reasons" ]; then result=boundary; fi
  printf 'capacity_profile profile=%s result=%s reasons=%s duration_seconds=%s read_workers=%s write_workers=%s target_read_rps=%s target_write_rps=%s achieved_rps=%s attainment_percent=%s read_success=%s read_errors=%s read_p99_ms=%s write_success=%s write_errors=%s write_p99_ms=%s readiness_errors=%s readiness_p99_ms=%s %s %s %s %s\n' \
    "$profile_name" "$result" "${reasons%,}" "$duration_seconds" "$read_workers" "$write_workers" "$read_rps" "$write_rps" "$achieved_rps" "$attainment_percent" \
    "$read_success" "$read_errors" "$read_p99" "$write_success" "$write_errors" "$write_p99" "$readiness_errors" "$readiness_p99" \
    "$integrity" "$app_resources" "$postgres_resources" "$collector_resources"
  [ "$result" = pass ]
}

last_safe_profile=none
boundary_profile=none
for step in 1 2 3 4; do
  case "$step" in
    1) profile=cap01; read_workers=24; write_workers=4; read_rps=100; write_rps=10 ;;
    2) profile=cap02; read_workers=40; write_workers=8; read_rps=200; write_rps=20 ;;
    3) profile=cap03; read_workers=48; write_workers=12; read_rps=300; write_rps=30 ;;
    4) profile=cap04; read_workers=48; write_workers=16; read_rps=500; write_rps=50 ;;
  esac
  if run_profile "$profile" "$profile_duration_seconds" "$read_workers" "$write_workers" "$read_rps" "$write_rps"; then
    last_safe_profile=$profile
  else
    boundary_profile=$profile
    break
  fi
done

compose up --detach --wait opscustodian
if ! run_profile caprecovery "$recovery_duration_seconds" 16 4 50 5; then
  echo "capacity recovery profile did not return to the bounded healthy envelope" >&2
  exit 1
fi

if ! wget_output=$(compose exec -T opscustodian wget -q -O - http://127.0.0.1:8080/readyz) || ! printf '%s' "$wget_output" | grep -q '"status":"ready"'; then
  echo "control plane was not ready after capacity recovery" >&2
  exit 1
fi

printf 'OpsCustodian capacity ramp passed: last_safe_profile=%s first_boundary_profile=%s recovery_profile=caprecovery threshold_type=experimental_not_slo\n' \
  "$last_safe_profile" "$boundary_profile"

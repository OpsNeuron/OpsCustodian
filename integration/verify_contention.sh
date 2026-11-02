#!/usr/bin/env sh
set -eu

integration_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

compose() {
  docker compose --project-directory "$integration_dir" -f "$integration_dir/compose.yaml" "$@"
}

: "${OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD:=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
: "${OPSCUSTODIAN_INTEGRATION_API_TOKEN:=integration-$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
: "${OPSCUSTODIAN_INTEGRATION_CONTENTION_WORKERS:=32}"
export OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD OPSCUSTODIAN_INTEGRATION_API_TOKEN

case "$OPSCUSTODIAN_INTEGRATION_CONTENTION_WORKERS" in
  ''|*[!0-9]*) echo "OPSCUSTODIAN_INTEGRATION_CONTENTION_WORKERS must be an integer between 2 and 64" >&2; exit 1 ;;
esac
if [ "$OPSCUSTODIAN_INTEGRATION_CONTENTION_WORKERS" -lt 2 ] || [ "$OPSCUSTODIAN_INTEGRATION_CONTENTION_WORKERS" -gt 64 ]; then
  echo "OPSCUSTODIAN_INTEGRATION_CONTENTION_WORKERS must be between 2 and 64" >&2
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

contention_summary=$(compose exec -T \
  -e OPSCUSTODIAN_TEST_API_TOKEN="$OPSCUSTODIAN_INTEGRATION_API_TOKEN" \
  -e CONTENTION_WORKERS="$OPSCUSTODIAN_INTEGRATION_CONTENTION_WORKERS" \
  opscustodian sh -c '
set -eu
result_dir=/tmp/opscustodian-contention-results
rm -rf "$result_dir"
mkdir -p "$result_dir"
same_payload="$result_dir/same.json"
conflict_payload="$result_dir/conflict.json"
sed "s/\"revision\": \"proposed\"/\"revision\": \"contention-shared\"/" /fixtures/scope-expansion/agentbom.after.json > "$same_payload"
sed -e "s/\"revision\": \"proposed\"/\"revision\": \"contention-shared\"/" -e "s/\"generator\": \"scope-expansion-example\"/\"generator\": \"contention-conflict\"/" /fixtures/scope-expansion/agentbom.after.json > "$conflict_payload"

post_identical() {
  worker=$1
  if wget -q -O /dev/null --header="Authorization: Bearer $OPSCUSTODIAN_TEST_API_TOKEN" --header="Content-Type: application/json" --post-file="$same_payload" http://127.0.0.1:8080/api/v1/snapshots; then
    echo success > "$result_dir/identical-$worker"
  else
    echo error > "$result_dir/identical-$worker"
  fi
}

worker=1
while [ "$worker" -le "$CONTENTION_WORKERS" ]; do
  post_identical "$worker" &
  worker=$((worker + 1))
done
wait

post_conflict() {
  worker=$1
  response="$result_dir/conflict-response-$worker"
  if wget -S -O /dev/null --header="Authorization: Bearer $OPSCUSTODIAN_TEST_API_TOKEN" --header="Content-Type: application/json" --post-file="$conflict_payload" http://127.0.0.1:8080/api/v1/snapshots 2> "$response"; then
    echo unexpected-success > "$result_dir/conflict-$worker"
  elif grep -q "409 Conflict" "$response"; then
    echo expected-conflict > "$result_dir/conflict-$worker"
  else
    echo error > "$result_dir/conflict-$worker"
  fi
  rm -f "$response"
}

worker=1
while [ "$worker" -le "$CONTENTION_WORKERS" ]; do
  post_conflict "$worker" &
  worker=$((worker + 1))
done
wait

identical_success=$(grep -l "^success$" "$result_dir"/identical-* | wc -l)
identical_errors=$(grep -l "^error$" "$result_dir"/identical-* | wc -l)
expected_conflicts=$(grep -l "^expected-conflict$" "$result_dir"/conflict-* | wc -l)
unexpected_success=$(grep -l "^unexpected-success$" "$result_dir"/conflict-* | wc -l)
conflict_errors=$(grep -l "^error$" "$result_dir"/conflict-* | wc -l)
rm -rf "$result_dir"
printf "identical_success=%s identical_errors=%s expected_conflicts=%s unexpected_success=%s conflict_errors=%s\n" "$identical_success" "$identical_errors" "$expected_conflicts" "$unexpected_success" "$conflict_errors"
')

metric() {
  key=$1
  printf '%s\n' "$contention_summary" | tr ' ' '\n' | sed -n "s/^$key=//p"
}

identical_success=$(metric identical_success)
identical_errors=$(metric identical_errors)
expected_conflicts=$(metric expected_conflicts)
unexpected_success=$(metric unexpected_success)
conflict_errors=$(metric conflict_errors)
for value in "$identical_success" "$identical_errors" "$expected_conflicts" "$unexpected_success" "$conflict_errors"; do
  case "$value" in ''|*[!0-9]*) echo "contention harness returned invalid counters" >&2; exit 1 ;; esac
done
if [ "$identical_success" -ne "$OPSCUSTODIAN_INTEGRATION_CONTENTION_WORKERS" ] || [ "$expected_conflicts" -ne "$OPSCUSTODIAN_INTEGRATION_CONTENTION_WORKERS" ] || [ "$identical_errors" -ne 0 ] || [ "$unexpected_success" -ne 0 ] || [ "$conflict_errors" -ne 0 ]; then
  echo "contention response contract failed: $contention_summary" >&2
  compose logs opscustodian >&2
  exit 1
fi

snapshot_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots WHERE revision = 'contention-shared';")
canonical_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots WHERE revision = 'contention-shared' AND bom->'metadata'->>'generator' = 'scope-expansion-example';")
orphan_findings=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshot_findings findings LEFT JOIN snapshots snapshots ON snapshots.organization_id = findings.organization_id AND snapshots.repository_id = findings.repository_id AND snapshots.id = findings.snapshot_id WHERE snapshots.id IS NULL;")
audit_duplicate_groups=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM (SELECT organization_id, event_id FROM audit_events GROUP BY organization_id, event_id HAVING count(*) > 1) duplicates;")
if [ "$snapshot_count" != "1" ] || [ "$canonical_count" != "1" ] || [ "$orphan_findings" != "0" ] || [ "$audit_duplicate_groups" != "0" ]; then
  echo "contention persistence integrity failed: snapshots=$snapshot_count canonical=$canonical_count orphan_findings=$orphan_findings audit_duplicate_groups=$audit_duplicate_groups" >&2
  exit 1
fi

attempt=0
while :; do
  persisted_audits=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM audit_events WHERE event->'attributes'->>'opscustodian.snapshot.revision' = 'contention-shared' AND event->'attributes'->>'opscustodian.snapshot.ingestion.result' = 'persisted';")
  conflict_audits=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM audit_events WHERE event->'attributes'->>'opscustodian.snapshot.revision' = 'contention-shared' AND event->'attributes'->>'opscustodian.snapshot.ingestion.result' = 'conflict';")
  if [ "$persisted_audits" -eq "$OPSCUSTODIAN_INTEGRATION_CONTENTION_WORKERS" ] && [ "$conflict_audits" -eq "$OPSCUSTODIAN_INTEGRATION_CONTENTION_WORKERS" ]; then
    break
  fi
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "contention audit contract failed: persisted=$persisted_audits conflicts=$conflict_audits" >&2
    exit 1
  fi
  sleep 1
done

compose exec -T opscustodian wget -q -O - http://127.0.0.1:8080/readyz | grep -q '"status":"ready"'
pending_spool_count=$(compose run --rm --no-deps --entrypoint sh opscustodian -c '
  set -- /audit-spool/audit-*.json
  if [ -e "$1" ]; then echo "$#"; else echo 0; fi
')
if [ "$pending_spool_count" != "0" ]; then
  echo "contention run left pending durable audit events" >&2
  exit 1
fi

printf 'OpsCustodian write contention passed: workers=%s identical_success=%s expected_conflicts=%s persisted_snapshots=%s persisted_audits=%s conflict_audits=%s\n' \
  "$OPSCUSTODIAN_INTEGRATION_CONTENTION_WORKERS" "$identical_success" "$expected_conflicts" "$snapshot_count" "$persisted_audits" "$conflict_audits"

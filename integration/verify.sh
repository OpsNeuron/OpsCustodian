#!/usr/bin/env sh
set -eu

integration_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

compose() {
  docker compose --project-directory "$integration_dir" -f "$integration_dir/compose.yaml" "$@"
}

: "${OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD:=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
: "${OPSCUSTODIAN_INTEGRATION_API_TOKEN:=integration-$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
export OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD OPSCUSTODIAN_INTEGRATION_API_TOKEN
export OPSCUSTODIAN_INTEGRATION_SNAPSHOT_RETENTION=24h
export OPSCUSTODIAN_INTEGRATION_SNAPSHOT_MINIMUM=1
export OPSCUSTODIAN_INTEGRATION_SNAPSHOT_PRUNE_INTERVAL=24h
export OPSCUSTODIAN_INTEGRATION_SNAPSHOT_PRUNE_BATCH=1

cleanup() {
  if [ "${OPSCUSTODIAN_INTEGRATION_KEEP:-false}" != "true" ]; then
    compose down --volumes --remove-orphans
  fi
}
trap cleanup EXIT INT TERM

compose up --detach --build --wait postgres collector opscustodian
compose exec -T postgres psql -v ON_ERROR_STOP=1 -U opscustodian -d opscustodian -c "SELECT version, name FROM schema_migrations ORDER BY version;"

attempt=0
until compose exec -T opscustodian wget -q -O - http://127.0.0.1:8080/readyz | grep -q '"status":"ready"'; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "OpsCustodian readiness did not become ready" >&2
    exit 1
  fi
  sleep 1
done

compose exec -T -e OPSCUSTODIAN_TEST_API_TOKEN="$OPSCUSTODIAN_INTEGRATION_API_TOKEN" opscustodian sh -c 'wget -q -O - --header="Authorization: Bearer $OPSCUSTODIAN_TEST_API_TOKEN" http://127.0.0.1:8080/api/v1/repositories' | grep -q 'integration:scan-input'
if compose exec -T -e OPSCUSTODIAN_TEST_API_TOKEN="$OPSCUSTODIAN_INTEGRATION_API_TOKEN" opscustodian sh -c 'wget -q -O /dev/null --header="Authorization: Bearer $OPSCUSTODIAN_TEST_API_TOKEN" http://127.0.0.1:8080/api/v1/repositories/repository-0000000000000000/bom'; then
  echo "repository-scoped credential unexpectedly accessed an unauthorized repository" >&2
  exit 1
fi
compose exec -T -e OPSCUSTODIAN_TEST_API_TOKEN="$OPSCUSTODIAN_INTEGRATION_API_TOKEN" opscustodian sh -c 'wget -q -O - --header="Authorization: Bearer $OPSCUSTODIAN_TEST_API_TOKEN" --header="Content-Type: application/json" --post-file=/config/policy-input.json http://127.0.0.1:8080/api/v1/policy/evaluate' | grep -q '"allowed":true'
compose logs opscustodian | grep -q '"opscustodian.policy.evaluation.result":"allowed"'
echo "Verifying PostgreSQL-backed historical drift"
if ! before_snapshot=$(compose exec -T -e OPSCUSTODIAN_TEST_API_TOKEN="$OPSCUSTODIAN_INTEGRATION_API_TOKEN" opscustodian sh -c 'wget -q -O - --header="Authorization: Bearer $OPSCUSTODIAN_TEST_API_TOKEN" --header="Content-Type: application/json" --post-file=/fixtures/scope-expansion/agentbom.before.json http://127.0.0.1:8080/api/v1/snapshots'); then
  echo "baseline snapshot ingestion failed" >&2
  compose logs opscustodian >&2
  exit 1
fi
if ! printf '%s\n' "$before_snapshot" | grep -q '"snapshotId":"snapshot-58c6a249b11fd7c7"'; then
  printf 'unexpected baseline snapshot response: %s\n' "$before_snapshot" >&2
  exit 1
fi
after_snapshot=$(compose exec -T -e OPSCUSTODIAN_TEST_API_TOKEN="$OPSCUSTODIAN_INTEGRATION_API_TOKEN" opscustodian sh -c 'wget -q -O - --header="Authorization: Bearer $OPSCUSTODIAN_TEST_API_TOKEN" --header="Content-Type: application/json" --post-file=/fixtures/scope-expansion/agentbom.after.json http://127.0.0.1:8080/api/v1/snapshots')
if ! printf '%s\n' "$after_snapshot" | grep -q '"snapshotId":"snapshot-0f2be90bc27aef1d"'; then
  printf 'unexpected proposed snapshot response: %s\n' "$after_snapshot" >&2
  exit 1
fi
drift_response=$(compose exec -T -e OPSCUSTODIAN_TEST_API_TOKEN="$OPSCUSTODIAN_INTEGRATION_API_TOKEN" opscustodian sh -c 'wget -q -O - --header="Authorization: Bearer $OPSCUSTODIAN_TEST_API_TOKEN" "http://127.0.0.1:8080/api/v1/repositories/repository-4b70fe32f822b795/drift?beforeSnapshotId=snapshot-58c6a249b11fd7c7&afterSnapshotId=snapshot-0f2be90bc27aef1d"')
if ! printf '%s\n' "$drift_response" | grep -q '"type":"capability-escalated"'; then
  printf 'unexpected historical drift response: %s\n' "$drift_response" >&2
  exit 1
fi
compose exec -T -e OPSCUSTODIAN_TEST_API_TOKEN="$OPSCUSTODIAN_INTEGRATION_API_TOKEN" opscustodian sh -c 'wget -q -O - --header="Authorization: Bearer $OPSCUSTODIAN_TEST_API_TOKEN" "http://127.0.0.1:8080/api/v1/graph?limit=2&action=kubernetes.deployments.update"' | grep -q '"repositoryId":"repository-4b70fe32f822b795"'
compose exec -T -e OPSCUSTODIAN_TEST_API_TOKEN="$OPSCUSTODIAN_INTEGRATION_API_TOKEN" opscustodian sh -c 'wget -q -O - --header="Authorization: Bearer $OPSCUSTODIAN_TEST_API_TOKEN" "http://127.0.0.1:8080/api/v1/audit-events?repositoryId=repository-4b70fe32f822b795&eventName=opscustodian.http.request.completed"' | grep -q '"opscustodian.snapshot.ingestion.result":"persisted"'
echo "Verifying bounded PostgreSQL snapshot retention"
compose exec -T postgres psql -v ON_ERROR_STOP=1 -U opscustodian -d opscustodian <<'SQL'
INSERT INTO snapshots
  (organization_id, repository_id, id, revision, generated_at, ingested_at, api_version, normalization_version, bom)
VALUES
  ('organization-0123456789abcdef', 'repository-4b70fe32f822b795', 'snapshot-aaaaaaaaaaaaaaaa',
   'retention-old-1', now() - interval '3 days', now() - interval '3 days', 'opscustodian.dev/v1alpha1', 'v1alpha1', '{}'),
  ('organization-0123456789abcdef', 'repository-4b70fe32f822b795', 'snapshot-bbbbbbbbbbbbbbbb',
   'retention-old-2', now() - interval '2 days', now() - interval '2 days', 'opscustodian.dev/v1alpha1', 'v1alpha1', '{}');
INSERT INTO snapshot_findings
  (organization_id, repository_id, snapshot_id, finding_id, finding_type, severity, asset_id, remediation_id, finding)
VALUES
  ('organization-0123456789abcdef', 'repository-4b70fe32f822b795', 'snapshot-aaaaaaaaaaaaaaaa',
   'retention-cascade-fixture', 'retention-fixture', 'low', 'fixture', 'fixture', '{}')
ON CONFLICT DO NOTHING;
SQL
compose restart opscustodian
compose up --detach --wait opscustodian
deleted_snapshot_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots WHERE organization_id = 'organization-0123456789abcdef' AND repository_id = 'repository-4b70fe32f822b795' AND id = 'snapshot-aaaaaaaaaaaaaaaa';")
batch_survivor_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots WHERE organization_id = 'organization-0123456789abcdef' AND repository_id = 'repository-4b70fe32f822b795' AND id = 'snapshot-bbbbbbbbbbbbbbbb';")
retained_latest_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshots WHERE organization_id = 'organization-0123456789abcdef' AND repository_id = 'repository-4b70fe32f822b795' AND id = 'snapshot-0f2be90bc27aef1d';")
orphan_finding_count=$(compose exec -T postgres psql -At -U opscustodian -d opscustodian -c "SELECT count(*) FROM snapshot_findings WHERE organization_id = 'organization-0123456789abcdef' AND finding_id = 'retention-cascade-fixture';")
if [ "$deleted_snapshot_count" != "0" ] || [ "$batch_survivor_count" != "1" ] || [ "$retained_latest_count" != "1" ] || [ "$orphan_finding_count" != "0" ]; then
  echo "snapshot retention invariant failed: deleted=$deleted_snapshot_count batch_survivor=$batch_survivor_count latest=$retained_latest_count orphan_findings=$orphan_finding_count" >&2
  exit 1
fi
compose exec -T opscustodian opscustodian scan --output /work/agentbom.integration.json /fixtures/scan-input
compose exec -T opscustodian opscustodian events --bom /work/agentbom.integration.json --output /work/events.integration.jsonl --otlp-endpoint http://collector:4318/v1/logs --allow-insecure-otlp
compose run --rm opa

attempt=0
until compose logs collector | grep -q 'OpsCustodian repository scan completed'; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "collector did not export the expected OpsCustodian event" >&2
    exit 1
  fi
  sleep 1
done

echo "OpsCustodian disposable integration harness passed."

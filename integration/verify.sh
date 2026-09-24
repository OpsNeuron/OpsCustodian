#!/usr/bin/env sh
set -eu

integration_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

compose() {
  docker compose --project-directory "$integration_dir" -f "$integration_dir/compose.yaml" "$@"
}

: "${OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD:=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
: "${OPSCUSTODIAN_INTEGRATION_API_TOKEN:=integration-$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
export OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD OPSCUSTODIAN_INTEGRATION_API_TOKEN

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

compose exec -T opscustodian sh -c 'wget -q -O - --header="Authorization: Bearer $OPSCUSTODIAN_API_TOKEN" http://127.0.0.1:8080/api/v1/repositories' | grep -q 'integration:scan-input'
compose exec -T opscustodian sh -c 'wget -q -O - --header="Authorization: Bearer $OPSCUSTODIAN_API_TOKEN" --header="Content-Type: application/json" --post-file=/config/policy-input.json http://127.0.0.1:8080/api/v1/policy/evaluate' | grep -q '"allowed":true'
compose logs opscustodian | grep -q '"opscustodian.policy.evaluation.result":"allowed"'
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

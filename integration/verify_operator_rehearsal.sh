#!/usr/bin/env sh
set -eu

repository_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

for command in git go gofmt docker od mktemp grep date; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "operator rehearsal requires $command" >&2
    exit 1
  fi
done

if [ -n "$(git -C "$repository_dir" status --porcelain --untracked-files=all)" ]; then
  echo "operator rehearsal requires a clean committed worktree" >&2
  exit 1
fi

commit=$(git -C "$repository_dir" rev-parse --verify HEAD)
if ! printf '%s\n' "$commit" | grep -Eq '^[0-9a-f]{40}$'; then
  echo "operator rehearsal could not resolve an exact commit" >&2
  exit 1
fi

if [ -n "${OPSCUSTODIAN_OPERATOR_EVIDENCE_FILE:-}" ]; then
  case "$OPSCUSTODIAN_OPERATOR_EVIDENCE_FILE" in
    /*) ;;
    *) echo "OPSCUSTODIAN_OPERATOR_EVIDENCE_FILE must be an absolute path" >&2; exit 1 ;;
  esac
  case "$OPSCUSTODIAN_OPERATOR_EVIDENCE_FILE" in
    "$repository_dir"|"$repository_dir"/*)
      echo "operator evidence must be written outside the repository" >&2
      exit 1
      ;;
  esac
  if [ ! -d "$(dirname -- "$OPSCUSTODIAN_OPERATOR_EVIDENCE_FILE")" ]; then
    echo "operator evidence directory must already exist" >&2
    exit 1
  fi
fi

if [ -n "$(docker ps -aq --filter label=com.docker.compose.project=opscustodian-integration)" ] ||
   [ -n "$(docker volume ls -q --filter label=com.docker.compose.project=opscustodian-integration)" ] ||
   [ -n "$(docker network ls -q --filter label=com.docker.compose.project=opscustodian-integration)" ]; then
  echo "operator rehearsal requires no pre-existing opscustodian-integration resources" >&2
  exit 1
fi

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/opscustodian-operator.XXXXXX")
source_dir="$temporary_root/source"
output_dir="$temporary_root/output"
mkdir -p "$output_dir"

: "${OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD:=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
: "${OPSCUSTODIAN_INTEGRATION_API_TOKEN:=integration-$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}"
export OPSCUSTODIAN_INTEGRATION_DATABASE_PASSWORD OPSCUSTODIAN_INTEGRATION_API_TOKEN
export OPSCUSTODIAN_INTEGRATION_KEEP=false

cleanup() {
  if [ -f "$source_dir/integration/compose.yaml" ]; then
    docker compose --project-directory "$source_dir/integration" \
      -f "$source_dir/integration/compose.yaml" \
      --profile recovery --profile upgrade --profile performance \
      down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  case "$temporary_root" in
    "${TMPDIR:-/tmp}"/opscustodian-operator.*) rm -rf -- "$temporary_root" ;;
    *) echo "refusing to remove unexpected operator rehearsal path" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM

started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
git clone --quiet --no-local --no-checkout "$repository_dir" "$source_dir"
git -C "$source_dir" checkout --quiet --detach "$commit"

if [ -n "$(git -C "$source_dir" status --porcelain --untracked-files=all)" ]; then
  echo "isolated operator checkout is not clean" >&2
  exit 1
fi

(
  cd "$source_dir"
  go run ./cmd/opscustodian-repocheck --root .
  test -z "$(gofmt -l .)"
  go mod tidy -diff
  go vet ./...
  go test -count=1 ./...
  go build -trimpath -o ./bin/opscustodian ./cmd/opscustodian

  ./bin/opscustodian scan --output "$output_dir/agentbom.json" ./examples/scan-input
  ./bin/opscustodian report --bom "$output_dir/agentbom.json" --output "$output_dir/opscustodian.html"
  ./bin/opscustodian diff \
    ./examples/scope-expansion/agentbom.before.json \
    ./examples/scope-expansion/agentbom.after.json > "$output_dir/drift.txt"
  grep -q 'capability-escalated' "$output_dir/drift.txt"
  grep -q 'CRITICAL' "$output_dir/drift.txt"

  sh ./integration/verify.sh
  sh ./integration/verify_backup_restore.sh
  sh ./integration/verify_upgrade.sh
  sh ./integration/verify_failure_recovery.sh
)

if [ -n "$(docker ps -aq --filter label=com.docker.compose.project=opscustodian-integration)" ] ||
   [ -n "$(docker volume ls -q --filter label=com.docker.compose.project=opscustodian-integration)" ] ||
   [ -n "$(docker network ls -q --filter label=com.docker.compose.project=opscustodian-integration)" ]; then
  echo "operator rehearsal left disposable Docker resources behind" >&2
  exit 1
fi

finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
summary=$(printf '%s\n' \
  'OpsCustodian operator rehearsal passed.' \
  "commit=$commit" \
  "startedAt=$started_at" \
  "finishedAt=$finished_at" \
  "go=$(go version)" \
  "docker=$(docker version --format '{{.Server.Version}}')" \
  'stages=source,quickstart,integration,backup-restore,upgrade,failure-recovery' \
  'cleanup=passed')
printf '%s\n' "$summary"

if [ -n "${OPSCUSTODIAN_OPERATOR_EVIDENCE_FILE:-}" ]; then
  printf '%s\n' "$summary" > "$OPSCUSTODIAN_OPERATOR_EVIDENCE_FILE"
  chmod 600 "$OPSCUSTODIAN_OPERATOR_EVIDENCE_FILE"
fi

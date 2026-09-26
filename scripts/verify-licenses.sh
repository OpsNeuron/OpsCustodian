#!/usr/bin/env sh
set -eu

go_licenses_version="v2.0.1"
policy_path="config/allowed-go-licenses.txt"
report_path="${1:-license-report.csv}"

allowed_licenses=$(tr -d '\r\n[:space:]' < "$policy_path")
if [ -z "$allowed_licenses" ]; then
  printf 'error: license allowlist is empty\n' >&2
  exit 1
fi

printf 'Checking Go dependency licenses with go-licenses %s\n' "$go_licenses_version"
go run "github.com/google/go-licenses/v2@${go_licenses_version}" check \
  --include_tests \
  --allowed_licenses="$allowed_licenses" \
  ./...

go run "github.com/google/go-licenses/v2@${go_licenses_version}" report \
  --include_tests \
  ./... > "$report_path"
test -s "$report_path"
printf 'License report written to %s\n' "$report_path"

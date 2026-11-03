#!/usr/bin/env sh
set -eu

integration_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# This wrapper intentionally fixes the first beta reference workload. Change the
# versioned profile in source when the beta workload contract changes; use
# verify_soak.sh directly for exploratory profiles.
export OPSCUSTODIAN_INTEGRATION_SOAK_DURATION_SECONDS=1800
export OPSCUSTODIAN_INTEGRATION_SOAK_READ_WORKERS=16
export OPSCUSTODIAN_INTEGRATION_SOAK_WRITE_WORKERS=4
export OPSCUSTODIAN_INTEGRATION_SOAK_READ_RPS=100
export OPSCUSTODIAN_INTEGRATION_SOAK_WRITE_RPS=10
export OPSCUSTODIAN_INTEGRATION_SOAK_SAMPLE_SECONDS=5

printf '%s\n' 'Running fixed beta-reference-v1 soak profile'
exec sh "$integration_dir/verify_soak.sh"

#!/bin/sh
set -u

action_input() {
  printenv "INPUT_$1" 2>/dev/null || true
}

# Docker actions preserve hyphens from action.yml input IDs in environment
# names. Underscore fallbacks keep direct/local execution convenient.
baseline_bom=$(action_input "BASELINE-BOM")
proposed_bom=$(action_input "PROPOSED-BOM")
scan_path=$(action_input "SCAN-PATH")
fail_on=$(action_input "FAIL-ON")
sarif_output=$(action_input "SARIF-OUTPUT")
max_file_size=$(action_input "MAX-FILE-SIZE")

: "${baseline_bom:=${INPUT_BASELINE_BOM:-}}"
: "${proposed_bom:=${INPUT_PROPOSED_BOM:-}}"
: "${scan_path:=${INPUT_SCAN_PATH:-.}}"
: "${fail_on:=${INPUT_FAIL_ON:-high}}"
: "${sarif_output:=${INPUT_SARIF_OUTPUT:-opscustodian.sarif}}"
: "${max_file_size:=${INPUT_MAX_FILE_SIZE:-2097152}}"

if [ -z "$baseline_bom" ]; then
  echo "error: baseline-bom is required" >&2
  exit 1
fi
if [ ! -f "$baseline_bom" ]; then
  echo "error: baseline Agent BOM does not exist: $baseline_bom" >&2
  exit 1
fi

if [ -z "$proposed_bom" ]; then
  proposed_bom=".opscustodian/current.agentbom.json"
  mkdir -p "$(dirname "$proposed_bom")"
  opscustodian scan \
    --format json \
    --max-file-size "$max_file_size" \
    --output "$proposed_bom" \
    "$scan_path" || exit 1
elif [ ! -f "$proposed_bom" ]; then
  echo "error: proposed Agent BOM does not exist: $proposed_bom" >&2
  exit 1
fi

mkdir -p "$(dirname "$sarif_output")"
opscustodian diff \
  --format sarif \
  --output "$sarif_output" \
  --fail-on "$fail_on" \
  "$baseline_bom" "$proposed_bom"
status=$?

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  printf 'sarif=%s\n' "$sarif_output" >> "$GITHUB_OUTPUT"
  printf 'proposed-bom=%s\n' "$proposed_bom" >> "$GITHUB_OUTPUT"
fi

exit "$status"

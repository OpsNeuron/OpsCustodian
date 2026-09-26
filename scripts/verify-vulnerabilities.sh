#!/usr/bin/env sh
set -eu

# Keep the scanner compatible with the minimum Go version declared in go.mod.
# The vulnerability database remains live and is queried on every invocation.
govulncheck_version="v1.7.0"

printf 'Running govulncheck %s against ./...\n' "$govulncheck_version"
exec go run "golang.org/x/vuln/cmd/govulncheck@${govulncheck_version}" ./...

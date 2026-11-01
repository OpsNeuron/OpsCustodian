@echo off
setlocal

rem Keep this version synchronized with verify-vulnerabilities.sh.
set "GOVULNCHECK_VERSION=v1.9.0"

echo Running govulncheck %GOVULNCHECK_VERSION% against ./...
go run golang.org/x/vuln/cmd/govulncheck@%GOVULNCHECK_VERSION% ./...
exit /b %ERRORLEVEL%

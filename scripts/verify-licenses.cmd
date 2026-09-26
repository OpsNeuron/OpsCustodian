@echo off
setlocal

rem Keep this version synchronized with verify-licenses.sh.
set "GO_LICENSES_VERSION=v2.0.1"
set "POLICY_PATH=config\allowed-go-licenses.txt"
set "REPORT_PATH=license-report.csv"
if not "%~1"=="" set "REPORT_PATH=%~1"

set /p ALLOWED_LICENSES=<"%POLICY_PATH%"
if not defined ALLOWED_LICENSES (
  echo error: license allowlist is empty 1>&2
  exit /b 1
)

echo Checking Go dependency licenses with go-licenses %GO_LICENSES_VERSION%
go run github.com/google/go-licenses/v2@%GO_LICENSES_VERSION% check --include_tests --allowed_licenses=%ALLOWED_LICENSES% ./...
if errorlevel 1 exit /b %ERRORLEVEL%

go run github.com/google/go-licenses/v2@%GO_LICENSES_VERSION% report --include_tests ./... > "%REPORT_PATH%"
if errorlevel 1 exit /b %ERRORLEVEL%
for %%I in ("%REPORT_PATH%") do if %%~zI EQU 0 (
  echo error: license report is empty 1>&2
  exit /b 1
)
echo License report written to %REPORT_PATH%

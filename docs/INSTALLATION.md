# Installation

OpsCustodian is a single Go binary. The offline `scan`, `findings`, `diff`, and
`report` workflows do not require a database, AI model, cluster, or network
connection.

## Build from source

Prerequisite: Go 1.25.13 or a newer supported patch release.

```bash
git clone https://github.com/OpsNeuron/OpsCustodian.git
cd OpsCustodian
go build -trimpath -o ./bin/opscustodian ./cmd/opscustodian
./bin/opscustodian version
```

Windows Command Prompt:

```bat
git clone https://github.com/OpsNeuron/OpsCustodian.git
cd OpsCustodian
go build -trimpath -o .\bin\opscustodian.exe .\cmd\opscustodian
.\bin\opscustodian.exe version
```

Continue with the [Quick Start](QUICKSTART.md).

## Install with Go

After a public tag is available, install a pinned version instead of relying on
an unreviewed moving branch:

```bash
go install github.com/opscustodian/opscustodian/cmd/opscustodian@v0.5.0-alpha
opscustodian version
```

The module path is lowercase by design. The repository URL remains
`github.com/OpsNeuron/OpsCustodian`.

## Release archive

Tagged releases provide archives for Linux amd64/arm64, macOS amd64/arm64, and
Windows amd64. Download the archive and `SHA256SUMS` from the same GitHub
release, verify the archive before extraction, and then run `opscustodian
version`.

Linux:

```bash
sha256sum --check SHA256SUMS --ignore-missing
tar -xzf opscustodian_0.5.0-alpha_linux_amd64.tar.gz
./opscustodian_0.5.0-alpha_linux_amd64/opscustodian version
```

Windows Command Prompt with `certutil`:

```bat
certutil -hashfile opscustodian_0.5.0-alpha_windows_amd64.zip SHA256
findstr /C:"opscustodian_0.5.0-alpha_windows_amd64.zip" SHA256SUMS
```

Compare the complete hashes before extracting. The release also publishes a
CycloneDX SBOM and GitHub build-provenance attestation.

## Container image

The repository Dockerfile currently packages the GitHub Action entrypoint. It
is not presented as a general-purpose server image. Build it only when testing
the Action contract:

```bash
docker build -t opscustodian:local .
```

The first local product evaluation should use the native binary. PostgreSQL,
OPA, OpenTelemetry Collector, Kubernetes, and multi-replica tests are separate
integration gates, not installation prerequisites.

## Trust boundary

- Repository scanning is offline and read-only.
- Generated Agent BOM and HTML files may contain repository metadata, but not
  secret values by design.
- Review parser diagnostics before interpreting missing results.
- Do not treat the experimental server or HA overlay as production-ready.

# Offline preflight

`opscustodian doctor` validates integration prerequisites without opening a
network connection, starting PostgreSQL, executing OPA, or exporting telemetry.
It emits only fixed check IDs and bounded statuses; environment values, paths,
repository identities, credential references, and backend errors are excluded.

Profiles:

```bash
opscustodian doctor --profile server
opscustodian doctor --profile policy --opa opa --policy policies/builtin
opscustodian doctor --profile release --format json
```

The `server` profile validates the secret-safe control-plane configuration,
strict RepositorySet file, GitHub App requirement matching, and private-key
shape. The `policy` profile checks that the selected OPA binary can be located
and the policy file or directory exists. `release` combines both profiles and
requires `LICENSE` under the selected repository root.

JSON output uses `opscustodian.dev/preflight/v1alpha1` and contains `ready` plus
ordered checks with `passed`, `failed`, or `skipped` status. Required failures
exit with code `2`. A successful offline preflight is not evidence that the
database, GitHub, OPA policy, Collector, or Kubernetes API works; those remain
separate final integration gates.

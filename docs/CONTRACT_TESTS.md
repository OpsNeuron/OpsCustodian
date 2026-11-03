# Public contract tests

OpsCustodian treats its machine-readable output as a product interface. Golden
tests lock representative byte-level output for:

- Agent BOM JSON;
- the current-state findings JSON envelope;
- current-state findings SARIF; and
- policy decision JSON.

The central contract registry and the authenticated `/api/v1/contracts`
response additionally lock every public contract version listed in
[`BETA_CONTRACT_FREEZE.md`](BETA_CONTRACT_FREEZE.md). The OpenAPI schema names
the complete response rather than accepting an unspecified success envelope.

Run the contract suite with:

```bash
go test ./internal/report -run TestPublicJSONContractsMatchGoldenFiles -v
```

The golden files live in `internal/report/testdata`. They deliberately have no
automatic update flag. If an intentional contract change makes the test fail:

1. decide whether the change is additive, compatible, or breaking;
2. update the relevant JSON Schema and contract documentation;
3. update every affected golden file in the same reviewed change; and
4. record a migration or version change before modifying a stable field.

Formatting differences are contract differences because downstream CI systems
may fingerprint or archive these artifacts. Dynamic timestamps and environment
data are excluded from the fixtures so the tests remain deterministic.

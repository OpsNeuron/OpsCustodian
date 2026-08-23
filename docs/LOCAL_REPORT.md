# Local inventory report

The `report` command renders an Agent BOM as a single self-contained HTML file:

```bash
opscustodian scan --source github:OpsNeuron/OpsCustodian --revision demo --output agentbom.json examples/scan-input
opscustodian report --bom agentbom.json --output opscustodian-report.html
```

Use `--source` before publishing or sharing a report. Without it, a local scan
records the absolute scanned path as its source, which is useful for local
traceability but can expose workstation directory names in screenshots.

It is intended for local review, CI artifacts, and sharing a point-in-time
inventory before the organization server and authenticated UI exist.

## Included views

- Inventory totals and asset-type coverage.
- Asset ownership, source, runtime, credentials, and evidence counts.
- Effective capabilities with visual effect classification.
- Evidence-backed relationship table.
- Parser diagnostics and inventory metadata.

## Security properties

- No server is started.
- No JavaScript is included.
- No fonts, stylesheets, images, or other network resources are loaded.
- Repository-derived strings are escaped by Go's `html/template` package.
- The renderer does not read credential values; the Agent BOM contract permits
  credential references only.

The report is an inventory surface, not an authorization decision. Risk and
policy enforcement remain in the `diff` and `check` pipelines.

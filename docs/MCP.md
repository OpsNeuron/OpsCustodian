# MCP server provenance and pinning

OpsCustodian analyzes configured MCP server execution identity without starting
the server, contacting a registry, or retaining secret-bearing command
arguments. Environment variable names remain credential references; values do
not enter the Agent BOM.

## Runtime classes

The repository-local parser distinguishes:

- exact npm and Python package versions;
- mutable package tags, ranges, `latest`, and unversioned packages;
- OCI images pinned by SHA-256 digest versus mutable tags;
- repository-local executables loaded from the same revision;
- paths escaping the repository boundary;
- system executables whose installed version is unknown;
- HTTPS and plaintext remote MCP endpoints.

`mcpServerProvenance` records the sanitized launcher, source type, registry,
package, version, pin type, integrity class, endpoint host, and evidence IDs.
A package version is treated as version-pinned, not cryptographically verified.
Only an OCI digest is content-addressed in the current offline model.

Unpinned or remotely mutable identities emit `mcpMutableRuntimeExposure`.
Plaintext remote endpoints additionally emit `mcpInsecureTransportExposure`.
The risk engine combines these controls with `mcp.tools.invoke` capabilities
and credential references. A provenance change on an existing MCP asset is
also treated as a supply-chain control change even when its invocation
capability remains otherwise identical.

## Secret-safe references

`runtime.reference` contains only a normalized execution identity such as
`npm:@scope/server@1.2.3`, `oci:registry/image@sha256:...`, or
`https://mcp.example.com/sse`. Arbitrary command arguments, URL user-info,
queries, and fragments are excluded because they may contain credentials.

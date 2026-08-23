# GitHub connector

The v0.6 GitHub integration begins with a hardened revision-discovery client.
Repository identity uses `github:owner/repository`; mutable refs are resolved to
an immutable 40- or 64-character commit SHA before any checkout is scanned.

Authentication configuration carries only a credential reference. The token is
resolved at request time, placed only in the Authorization header, and never
stored in RepositorySet, Agent BOM, results, audit events, or returned errors.
Public repositories may omit the credential reference.

The client uses HTTPS by default, rejects endpoint userinfo/query/fragment,
prevents redirects to avoid credential forwarding, bounds time and response
size, and does not expose response bodies. Rate limits, network failures, and
server failures are classified as transient for the existing bounded retry
policy; authentication, authorization, missing repository, and malformed
responses fail permanently.

Current tests use local HTTP fakes. Real GitHub provider, authentication, and
rate-limit tests remain subsequent work.

The archive materialization boundary accepts a streamed ZIP only into an
OpsCustodian-owned temporary workspace. It enforces compressed size, extracted
size, and entry-count ceilings; strips exactly one GitHub top-level directory;
and rejects traversal, backslashes, absolute paths, symlinks, special files,
case-insensitive duplicates, and multiple roots. Extracted permissions are
fixed rather than inherited, cancellation is honored, and cleanup is
idempotent.

Archive acquisition performs at most two requests. The authenticated API
request may redirect only to an explicitly allowlisted HTTPS archive host. The
second request is constructed from scratch without Authorization and cannot
redirect again. Signed query parameters are accepted for the allowlisted target
but are never returned in errors. Direct archive responses are also supported;
status and transport failures reuse the bounded transient retry contract.

`GitHubConnector` now composes revision discovery, unchanged-SHA short-circuit,
controlled archive acquisition, hardened materialization, the production parser
pipeline, and deterministic Agent BOM generation. Temporary checkout cleanup is
mandatory and cleanup failure invalidates the fetch rather than silently
leaking workspace state.

Operational RepositorySet entries support `connector: github`, a mutable `ref`,
and an optional environment credential reference. References are constrained to
`env:OPSCUSTODIAN_GITHUB_TOKEN_*`; arbitrary environment variables cannot be
selected, preventing repository configuration from exfiltrating unrelated
database or platform secrets. The control-plane process registers local and
GitHub connectors behind the same orchestrator.

Example:

```json
{
  "source": "github:acme/platform",
  "connector": "github",
  "ref": "main",
  "credentialReference": "env:OPSCUSTODIAN_GITHUB_TOKEN_PLATFORM"
}
```

The referenced environment variable contains the token at runtime. The token
must not be placed directly in RepositorySet or committed to source control.

The GitHub App authentication boundary is defined separately from static token
resolution. It validates `github-app:installation:<id>` references, caches only
short-lived installation tokens, refreshes them before expiry, coalesces
concurrent refreshes per installation, honors caller cancellation, and replaces
provider failures with secret-safe errors. The provider parses RSA keys of at
least 2048 bits, signs bounded RS256 JWTs, exchanges them through the GitHub API,
rejects redirects and oversized or invalid responses, and preserves transient
rate-limit/server classification without returning response bodies.

RepositorySet activation remains disabled until the App ID and private-key
configuration boundary is complete. Private keys will be loaded from an
external runtime reference and must never be embedded in RepositorySet.

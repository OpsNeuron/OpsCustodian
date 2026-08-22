# Multi-repository ingestion

The ingestion orchestrator is the persistence-neutral boundary between future
repository connectors and the immutable OpsCustodian snapshot store.

Each configured repository is fetched independently. The connector receives
the last known revision and may return `Unchanged`, allowing conditional Git
requests and avoiding unnecessary parsing and persistence. A changed Agent BOM
must retain the configured repository source; cross-repository output is
rejected before storage.

Batch execution has a required concurrency limit. One repository failure or
immutable revision conflict does not prevent other repositories from being
processed. Results retain configuration order so automation and audit systems
receive deterministic output even when fetches complete out of order.

Each repository may have an independent timeout. Connectors explicitly mark
retry-safe transient failures; unmarked errors are permanent and are attempted
once. Transient failures use a bounded exponential backoff and a fixed maximum
attempt count, preventing authentication and contract errors from causing retry
storms. Result records expose attempt count and a bounded failure class without
requiring callers to parse provider error strings.

The scheduler runs one batch immediately at startup and measures the next
interval from batch completion. Batches therefore cannot overlap. A bounded
cryptographic jitter spreads provider traffic across replicas, while a copied
repository configuration prevents concurrent mutation. Each completion is
reported through an observer intended for audit and metrics; observer failure
stops the scheduler instead of allowing unaudited background ingestion.

Connectors are selected through a validated registry. Repository configuration
separates the stable BOM source from connector type, materialized location,
revision, boundaries, and file-size policy; it contains no credential values.
The initial `local` connector requires a clean absolute directory, reuses the
production parser pipeline, skips known revisions, and removes execution time
from immutable BOM content so independent instances produce the same document
for the same source and revision.

Repository sets use the versioned `opscustodian.dev/ingestion/v1alpha1`
contract and are loaded only from a bounded, regular, non-symlink absolute
file. JSON decoding is strict, duplicate sources and unsafe paths are rejected,
and schedule/retry limits are validated before runtime construction. The schema
intentionally has no token, password, or credential fields; provider secrets
will be referenced from environment or a secret manager rather than serialized
into repository configuration.

Current tests use in-memory stores and fake connectors. Real GitHub/GitLab
authentication, rate limits, webhooks, polling, retries, and distributed job
coordination remain future integration work.

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

Current tests use in-memory stores and fake connectors. Real GitHub/GitLab
authentication, rate limits, webhooks, polling, retries, and distributed job
coordination remain future integration work.

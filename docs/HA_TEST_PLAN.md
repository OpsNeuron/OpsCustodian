# High-availability validation plan

The `ha-experimental` Kustomize overlay is an opt-in test artifact, not a
production recommendation. The base remains single-replica until every gate in
this document passes against real PostgreSQL and a disposable Kubernetes
cluster, planned on Docker Desktop.

## Invariants under test

1. Exactly one healthy process reports `scheduler-role=leader` and the other
   reports `standby` during a schedule cycle.
2. Only the active fencing generation can commit snapshots.
3. Graceful leader termination releases or expires its lease and a standby
   becomes leader without duplicate immutable snapshots.
4. Abrupt leader loss causes takeover only after TTL expiry.
5. A paused or partitioned former leader cannot commit after another process
   increments the fencing token.
6. PostgreSQL restart, connection exhaustion, and renewal timeout make affected
   processes not-ready without exposing DSNs, holder IDs, tokens, or errors.
7. Rolling updates maintain at least one ready API replica and never run two
   authorized ingestion commits concurrently.
8. A leader retains one fencing generation across multiple schedule intervals;
   a standby retries at the renewal cadence and does not run a duplicate cycle.

## Evidence to retain

- rendered and server-side validated manifests;
- bounded `/readyz` snapshots from both Pods;
- scheduler audit events showing only leader, standby, and lease-lost roles;
- `scheduler_leases` holder-independent token/expiry transitions;
- immutable snapshot and Finding counts before and after each failure;
- Pod events, rollout status, PostgreSQL logs, and test timestamps;
- cleanup output proving only disposable test resources were removed.

## Final Docker Desktop sequence

1. Start Docker Desktop and verify the Linux engine and Kubernetes API.
2. Run the existing isolated Compose harness for PostgreSQL, OPA, and OTLP.
3. Execute real concurrent lease acquire/renew/release and migration rollback
   tests against the disposable PostgreSQL container.
4. Render `deploy/kubernetes/overlays/ha-experimental`, run server-side dry-run,
   then apply it only to a disposable namespace or cluster.
5. Exercise graceful termination, forced container loss, network interruption,
   database restart, rolling update, and rollback scenarios.
6. Run Linux race/load tests in containers and preserve the evidence above.
7. Delete only resources whose project/namespace scope was verified first.

The overlay may graduate from `ha-experimental` only after these results are
repeatable and documented. Static rendering or unit tests alone cannot satisfy
this gate.

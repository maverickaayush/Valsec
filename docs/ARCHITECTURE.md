# Valsec architecture

The upload API validates and expands configuration files, detects each device vendor independently, and creates one `Config` lifecycle per file. Celery dispatches each audit separately. Cisco, Juniper, and Fortinet adapters emit the shared schema; the generic adapter emits source-backed unknown findings.

The matcher checks user-and-vendor-scoped approved mappings before local Ollama is asked for proposals. Valid proposals are persisted as `probable`; missing or invalid proposals remain `unverified`. Both require operator approval. Only `confirmed` findings are assembled into the neutral configuration passed to compliance.

Framework catalogues contain deterministic predicates. The compliance engine alone produces verdict, severity, and score. Remediation selects a deterministic vendor template first, then may request a validated local Ollama configuration block marked as AI generated. Reports render persisted deterministic results.

## Seed-based neighbor discovery

Discovery is an additive evidence and orchestration layer in front of the
existing pull path. A `DiscoverySession` owns persistent `DiscoveredDevice`
records, and each successfully pulled device links to the ordinary `Config`
that Celery audits. Sessions use breadth-first traversal with hard depth and
device limits, address deduplication, per-device failure isolation, and target
resolution/pinning before every connection.

Valsec authenticates to each eligible seed over SSH and executes a fixed vendor
command set. Cisco discovery prefers CDP and then LLDP; Juniper uses LLDP;
Linux/OpenWrt uses LLDP when installed plus `ip neigh show` and
`/proc/net/arp`. Kernel neighbor evidence supplies an address, MAC, interface,
and bounded raw evidence, but does not prove that the host is a router or
identify its vendor.

An advertised vendor/profile can be processed automatically when the operator
explicitly allows reuse of the seed credentials. A passive-only candidate is
persisted as `needs_input`. The UI asks for the minimum missing fixed profile
and credentials; it never asks the operator to re-enter the discovered IP.
Valsec then revalidates the stored target and uses the same pull, `Config`
persistence, and Celery dispatch as direct ingestion. Unrelated passive hosts
can be marked `skipped`. This avoids subnet scanning, credential spraying,
vendor guessing, and a second audit implementation.

SSH devices retain their fixed vendor read commands. The Cirotech
profile uses its Linux Telnet shell and the documented read-only `mib all`
configd dump. It never invokes the separate `mib commit` write operation.
Telnet is restricted to private/link-local addresses, is plaintext, and is
intended only for an isolated management LAN where the appliance offers no SSH.
Credentials remain request-local and are never stored on discovery records.
Direct pull and the earlier evidence/revalidation endpoints remain available
for compatibility.

## Device registry, history, and drift

Every new configuration audit is linked to a durable `Device` in the existing
ingestion transaction. Uploads resolve by exact vendor and display name when no
address exists. Direct and discovered pulls resolve by exact vendor and the
already validated, pinned management address. PostgreSQL advisory transaction
locks and indexed lookups serialize address-based create-or-match without a
table scan. Authenticated deployments place the current user UUID in the
nullable organization placeholder; device endpoints apply the same hidden-404
ownership pattern as configuration endpoints.

The audit worker updates `first_seen_at` and `last_audited_at` only when its
existing lifecycle reaches `complete`. Decommissioning changes `is_active` but
does not delete linked configurations or results. A baseline must be a
completed configuration belonging to the same device.

`compliance/drift.py` is pure deterministic Python. It compares persisted
control verdicts and produces the same `difflib.unified_diff` format used by
remediation push. It has no database, network, or AI dependency. Fleet scoring
uses SQL window functions to select only the latest completed configuration per
active device; failing controls are grouped from that same latest relation.

## Observability

`/health` reports process liveness. `/ready` runs bounded database, Redis, and
Ollama reachability checks concurrently; it performs no inference. Production
responses identify unavailable dependencies without returning connection
details. Celery worker concurrency is sourced from `MAX_CONCURRENT_AUDITS`,
which also documents the database-pool sizing relationship. Compose defines
health checks for PostgreSQL, Redis, backend, worker, and frontend.

## Opt-in credential vault (P1-1)

The vault is dark by default behind `ENABLE_CREDENTIAL_VAULT`. Its local backend
derives a Fernet key from the dedicated `CREDENTIAL_VAULT_KEY`; the session and
CSRF `SECRET_KEY` is never reused. PostgreSQL stores only the encrypted opaque
reference plus non-secret username/type metadata. API responses never contain
the reference or decrypted secret. Successful stored-credential pulls append a
`CredentialAccessLog` event after the connector returns, and logging failure is
warned without turning an otherwise successful device pull into a failure.

P1-1 reuses `Device.org_id` as the already-live user UUID ownership boundary.
An unowned device is claimed by its first authenticated network/vault accessor;
another user receives `403` before a connector or secret backend is reached.
This is explicitly a stopgap pending P1-3 Organizations/Roles and must not be
extended as a general permissions model. Local `REQUIRE_AUTH=false` calls bypass
the ownership helpers and retain request-supplied credentials unchanged.

Only direct manual SSH pull can retrieve a stored credential in P1-1. Discovery
continues to accept request-scoped credentials, scheduling does not exist, and
remediation approval/PUSH retains its existing local-only policy.

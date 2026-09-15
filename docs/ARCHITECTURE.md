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
table scan. Authenticated deployments link devices to real Organizations;
Membership roles apply the same hidden-404 isolation pattern as device APIs.

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

## Opt-in credential vault

The vault is dark by default behind `ENABLE_CREDENTIAL_VAULT`. Its local backend
derives a Fernet key from the dedicated `CREDENTIAL_VAULT_KEY`; the session and
CSRF `SECRET_KEY` is never reused. PostgreSQL stores only the encrypted opaque
reference plus non-secret username/type metadata. API responses never contain
the reference or decrypted secret. Each successful server-side retrieval appends
a `CredentialAccessLog` event; logging failure is warned without turning an
otherwise successful device operation into a failure.

`Device.org_id` is a real Organization foreign key. An unowned
device is claimed into the authenticated user's personal Organization, and
owner/operator/viewer memberships define access. Local `REQUIRE_AUTH=false`
calls bypass memberships and retain request-supplied credentials unchanged.

Organizations carry an opt-in `require_separate_remediation_approver` policy.
The compatible default permits an owner to approve their own campaign. When an
owner enables dual control, a different owner must approve; operators can still
propose and execute already-approved campaigns, and viewers remain read-only.

Direct pulls, recurring audits, and Network Missions retrieve stored credentials
through the same server-only service. Legacy discovery continues to accept
request-scoped credentials for compatibility, and the legacy remediation
approval/PUSH endpoint retains its local-only policy.

## Network Mission orchestration

`NetworkMission` is the trace root for a bounded operation. A
`NetworkMissionDevice` records the seed or one authenticated-neighbor evidence
node, eligibility state, Device identity, and linked Config. Append-only
`NetworkMissionEvent` rows record sanitized transitions. A
`RemediationCampaign` groups one framework/control, while each
`RemediationCampaignTarget` preserves the individual finding, vendor-specific
immutable `RemediationAction`, and final device outcome.

The mission worker performs a bounded BFS on the `network_missions` queue. It
does not iterate over an IP range. Only a CDP/LLDP candidate with an established
supported vendor can become a Device automatically; passive ARP candidates are
persisted as identity-unverified. Cycles are deduplicated by pinned address and
both depth and count are capped. A candidate must also pass the central target
guard, requested mission CIDRs, optional deployment-wide
`AUTHORIZED_NETWORKS`, organization isolation, connector support, and an exact
device-bound credential lookup.

Eligible nodes call `pull_with_stored_credential()`, which calls the existing
connector and `persist_and_dispatch_configs()` path. Mission audits therefore
produce ordinary Config, NormalizedFinding, ComplianceResult, and Report rows.
Fleet summaries are views over those persisted rows. The mission layer does not
change normalization or verdict logic and makes no AI call of its own.

Campaign creation accepts only persisted deterministic remediation text; AI
fallback text is excluded. Owner approval creates/reuses the same immutable
per-finding `RemediationAction` used by manual push. Execution remains one
target per task and calls the existing snapshot/apply/re-read/diff connector.
Terminal targets distinguish verified, already-compliant, failed, unreachable,
and rolled-back outcomes, allowing aggregate partial completion without a
broadcast command. A verified post-change snapshot becomes an ordinary Config,
is audited by the existing worker, and is linked as the target's verification
Config; final posture uses those completed deterministic results.

Task arguments are UUIDs only. Credential plaintext is retrieved within a
worker and discarded after one connector operation. Credential access is
linked to the mission. Run default, `scheduled_audits`, and `network_missions`
workers separately; set mission worker concurrency from
`MISSION_MAX_CONCURRENT_OPERATIONS` (default 5). Approved per-device changes and
campaign finalization run on the separate `remediation` queue, bounded by
`REMEDIATION_MAX_CONCURRENT_OPERATIONS` (default 3), so fleet activity cannot
occupy interactive worker slots and configuration mutation cannot starve
discovery orchestration.

# Valsec final engineering handoff

Updated: 14 September 2026 (Asia/Kolkata)

## Submission state

Valsec is a standalone network-device configuration compliance product. The prior web assessment product, its routes, task graph, data tables, Docker services, frontend pages, documentation, tools, tests, and assets have been removed from the active tree. PostgreSQL, Redis, Celery, FastAPI, local Ollama, WeasyPrint reporting, authentication/ownership primitives, and the Valsec frontend remain.

## Implemented product

- Cisco IOS/IOS-XE, Juniper JunOS, and Fortinet FortiOS parser adapters.
- Generic unsupported-vendor normalizer that preserves every non-empty source line without claiming recognition.
- Per-file vendor detection for single, multipart, and ZIP uploads; one independent `Config` and Celery job per member.
- Safe in-memory ZIP processing with path, member-count, per-file, archive, expansion, extension, text, and filename bounds.
- Vendor-neutral normalized schema with raw source line and line number provenance.
- Local Ollama structured mapping proposals. Fenced JSON, surrounding whitespace, serialized scalar variations, and validated single-proposal objects are normalized safely.
- Confidence semantics: deterministic or approved/reused findings are `confirmed`; a valid Ollama proposal is `probable`; no valid proposal is `unverified`. Probable and unverified findings both block compliance until operator approval.
- Persistent mappings isolated by authenticated user and exact vendor scope, with separate safe local single-operator scope.
- Transactional, row-locked, duplicate-safe training. A broker dispatch failure leaves the audit in a recoverable `awaiting_training` state and returns an explicit service error.
- Deterministic compliance engine and score. AI cannot produce verdict, deterministic severity, or score.
- CIS Cisco IOS (23 controls), CIS Juniper JunOS (11 controls), NIST SP 800-53 Rev. 5 (8 neutral and 7 Fortinet controls), DISA Network Device STIG V1R1 (6 controls), and ISO/IEC 27001:2022 Annex A (6 controls).
- Explicit rejection/substitution rules prevent Fortinet or unknown vendors from silently using the Cisco/Juniper CIS catalogue.
- Deterministic Cisco, Juniper, and FortiOS remediation; validated local Ollama fallback only when a template is absent, with an `ai_generated_fallback` marker.
- Valsec PDF with device/vendor/OS, framework/version, timestamp, score, PASS/FAIL/N/A, severity, control, observed evidence, requirement, CLI remediation, and AI fallback marker.
- Real API-backed frontend for dashboard, mixed uploads, fleet state, training, framework selection, results, remediation, and PDF.

The NIST, DISA, ISO, and vendor catalogues outside the Cisco CIS set are representative deterministic technical coverage. They do not claim full certification or accreditation coverage.

## Confidence fix

`backend/tasks/audit_orchestrator.py` now persists a validated Ollama mapping as `ConfidenceTier.probable` with `mapping_source=ai_proposal`. Missing, malformed, unsafe, or unavailable proposals remain `ConfidenceTier.unverified`. `GET /api/configs/{id}/unverified`, status counts, and the training queue include both tiers and expose the persisted confidence. `POST /train` converts the finding to confirmed only after operator approval; a resumed audit rebuilds it from the approved learned mapping as confirmed.

Regression coverage proves valid proposal → probable, absent/malformed proposal → unverified, API confidence exposure, and operator approval → confirmed.

## Removed legacy product components

Removed scanner-specific FastAPI routes, Celery tasks, analysis/scoring modules, report renderer/template, target network guard, scanner credentials/config, Modal functions, ZAP scripts/session data, vulnerable practice services, scanner dependencies and binaries, scanner frontend routes/components/API code, scanner tests, screenshots, documentation, automation scripts/logs, and Nimbus prototype sources/archive. Docker Compose now has only PostgreSQL, Redis, backend, worker, and frontend. The backend image contains only Valsec/PDF dependencies and runs as an unprivileged user.

The database migration chain is a Valsec-only baseline followed by migrations for user-scoped learned mappings, remediation actions, and discovery sessions. The active ORM contains only Valsec authentication, audit, compliance, reporting, remediation, and discovery entities.

## Verification results

### Focused automated verification

- `python3 -m pytest tests -q`: **195 passed**, 22 deprecation warnings, 0 failures.
- `python3 -m compileall -q backend migrations`: passed.
- `git diff --check`: passed.
- `npm run typecheck`: passed.
- `npm run build`: passed on Next.js 16.3.5; all nine Valsec routes built and TypeScript ran during production build.
- `docker compose config -q`: passed.
- Clean backend, worker, and frontend Docker images: built successfully.
- Fresh PostgreSQL volume: Alembic upgraded `base → f8c2a9d4e761 → 9b4f1d7e2c30` successfully.
- Production dependency audit after the Next.js patch: 0 critical/high findings and 1 moderate transitive finding. Development dependency audit still reports advisories in build-time tooling.

### Real Docker/PostgreSQL/Redis/Celery/Ollama E2E

A fresh `valsec_final` Compose project was tested against local `qwen2.5:7b`:

- Hardened Cisco + CIS: complete, 100%, 21 PASS / 0 FAIL / 2 N/A, PDF returned `%PDF`.
- Vulnerable Cisco + CIS: complete, 0%, 0 PASS / 13 FAIL / 10 N/A, deterministic remediation and PDF generated.
- Juniper + CIS: complete, 100%, 11 PASS, PDF generated.
- Fortinet + NIST: complete, 100%, 7 PASS, PDF generated.
- Mixed ZIP (Cisco + Juniper + Fortinet + NewCo NOS): the three supported adapters completed independently while NewCo paused at `awaiting_training`.
- NewCo unknown syntax received a live Ollama `ssh.version` proposal at 0.95 and persisted as `probable` / `ai_proposal`.
- Operator approval persisted a `NewCo NOS` learned mapping, resumed the audit, and completed it with a PDF.
- A later mixed multipart upload containing Cisco plus the identical NewCo syntax completed both devices without training; the NewCo finding was `confirmed` / `learned_mapping`.
- User/vendor isolation, duplicate submission, concurrent training, unsafe ZIP, ownership, report authorization, and dispatch-failure recovery are covered by passing focused tests.
- A live missing-template Cisco remediation call returned a complete `configure terminal … end` block marked `ai_generated_fallback`.
- Frontend `http://localhost:3000` served successfully and fetched `/api/configs` through its real same-origin proxy.

## Security review

- Deterministic compliance is isolated in `backend/compliance/`; Ollama is called only from mapping/remediation paths.
- Unverified and probable syntax cannot reach compliance.
- Config, training, result, and report endpoints share owner checks when `REQUIRE_AUTH=true`.
- Learned mappings use user/vendor partial unique indexes and matching filters.
- ZIP members are processed in memory and traversal is rejected; limits prevent unbounded member and expansion abuse.
- Model prompts serialize untrusted values as JSON. Responses are bounded, schema/type checked, and remediation commands reject destructive/diagnostic output.
- Secrets are environment-driven, `.env` and generated keys are excluded, production startup rejects placeholders, and containers run without root privileges.
- Audit advisory locks and training row locks prevent concurrent corrupt transitions; failed dispatch is explicit and recoverable.

## Files added or finalized

- `backend/normalizer/{generic,fortios}.py`
- `backend/remediation/fortios_remediation.py`
- `backend/tests/test_fortios_normalizer.py`
- `backend/tests/sample_configs/{fortinet_hardened,fortinet_vulnerable,unknown_vendor_training,mixed_vendor_fleet}.*`
- `docs/{ARCHITECTURE,SECURITY}.md`
- Clean Valsec baseline migration and Valsec-only Docker/CI/runtime configuration.

See the Git diff for the complete removal list and all modified integration files.

## Remaining limitations

- Non-CIS framework catalogues are representative subsets, not complete certification content.
- Fortinet supports the implemented NIST catalogue; other Fortinet framework combinations return an explicit unsupported response.
- Generic-vendor onboarding can only evaluate controls supported by schema fields an operator has taught; it is not a hand-written vendor adapter.
- Ollama availability and output quality affect proposal/remediation convenience only. Manual training and deterministic results remain available.
- Optional hosted authentication APIs remain available, while the submission frontend is optimized for the default local single-operator demo and has no account-management screens.
- One moderate transitive frontend production advisory remains in `baseline-browser-mapping`; no high or critical production advisory remains.
- Remediation approval/PUSH remains disabled when `REQUIRE_AUTH=true`. Pull/discovery uses the P1-3 Organization membership boundary; local mode remains unchanged.
- Cisco applies running configuration only. Junos uses a five-minute confirmed commit. FortiOS has no automatic push procedure in this pass, and risky generic/UCI changes are always manual.
- First-contact SSH currently accepts the appliance host key for the ephemeral connector session. Operators should use a trusted management LAN; persistent fingerprint enrollment is a future hardening item.

## Local device pull and approved push (13 September 2026)

- Added a resolve-then-pin SSH target guard. Private, public, and ordinary link-local device addresses are accepted; loopback, IPv4-mapped loopback, and `169.254.169.254` are blocked.
- `POST /api/configs/pull-device` runs exactly one fixed read command (`show running-config`, Junos display-set, or `uci show`), stores no credentials, creates a normal queued `Config`, and dispatches the existing audit task. Connector failures create no Config row.
- Added `RemediationAction` and migration `c4e8a2f91b76`. Approval copies existing `ComplianceResult.remediation_cli` once; the apply endpoint accepts no command text and passes only the stored approval to the connector.
- Cisco push enters configuration mode and never sends `write memory` or a startup-copy command. Junos sends `commit confirmed 5`, re-pulls to verify reachability, and only then sends the final commit. A failed re-pull leaves the device to auto-rollback and reports that state.
- Generic/UCI push accepts only a narrow UCI mutation grammar, commits and uses fixed reload commands. Session-affecting UCI changes are refused even when the caller sets risky confirmation. FortiOS automatic push is explicitly unsupported.
- Every successful apply stores pre/post snapshots and a unified diff. The results API and Valsec UI expose approval/apply state and diff evidence. SSH passwords remain only in `SecretStr` request objects and connector call memory.
- New focused tests: target guard, SSH pull, risk classification, SSH push, pull router, and push router. The complete active backend suite reports **243 passed**; the focused connector/router group reports **48 passed**. Frontend typecheck and production build pass.
- Docker images rebuilt, Alembic upgraded both the retained database and a disposable fresh PostgreSQL database through `base → f8c2a9d4e761 → 9b4f1d7e2c30 → c4e8a2f91b76`, backend/worker/frontend started, and all three new API paths appeared in the live OpenAPI schema. A real read-only pull from the supplied Dropbear/OpenWrt device succeeded, stored 7,307 characters, and queued Config `7e919f1b-e865-46a8-91b6-8a74da6c34cc`. The existing Ollama request timed out cleanly after its bounded retries, so the audit reached `awaiting_training` with 227 source-backed unverified lines. Paramiko 4 is pinned because this appliance offers only an `ssh-rsa` host key; modern algorithms remain preferred. No live remediation was pushed.

## Exact next human actions

1. Review the working-tree diff, especially the deliberate removal of the old product and rewritten clean baseline migration.
2. Copy `.env.example` to `.env`, set strong production secrets if exposing the service, and confirm `qwen2.5:7b` is installed in local Ollama.
3. Use `backend/tests/sample_configs/mixed_vendor_fleet.zip`; provide vendor hint `unknown.conf = NewCo NOS` in the UI to demonstrate the learning gate.
4. If scope continues after submission, expand the representative NIST/DISA/ISO catalogues with reviewed authoritative control mappings and vendor evidence tests.

## Seed neighbor discovery and Cirotech Telnet pull (13 September 2026)

- Added modular authenticated discovery in `backend/connectors/neighbor_discovery.py`. It prefers LLDP management data when advertised and merges it with valid `ip neigh` and `/proc/net/arp` entries. Kernel entries are candidates, not asserted router identities.
- Added `POST /api/configs/discover-neighbors` and `POST /api/configs/pull-discovered-device`. The pull endpoint repeats discovery before connection, then uses the existing Config persistence, Celery dispatch, normalization, training, compliance, and report lifecycle.
- Added a constrained Cirotech Linux-shell Telnet connector. It permits only private/link-local pinned targets, accepts no operator command text, runs the appliance-documented read-only `mib all` configd dump, bounds output to 5 MiB, sanitizes failures, closes sessions, and never persists credentials. It never invokes the separate `mib commit` write operation. Telnet is plaintext and is intended only for the isolated management LAN.
- Added the Valsec **Discover & Audit Neighbor** UI. The operator authenticates to the seed, selects from returned evidence, supplies that neighbor's credentials, and enters the existing status/training/results views.
- Live OpenWrt discovery from `192.168.1.2` succeeded from both the host process and rebuilt Docker backend. Cirotech appeared as `192.168.1.1`, MAC `c4:70:0b:bc:19:30`, interface `br-lan`, evidenced by neighbor and ARP tables. LLDP supplied no Cirotech advertisement, matching the hardware.
- The active backend suite reports **255 passed**. The focused connector/discovery/audit/training run reports **94 passed**. Backend compilation, frontend typecheck, and frontend production build pass. Backend, worker, and frontend images were rebuilt; the live dashboard/API are serving the new flow.
- Live shell inspection identified Realtek Luna SDK 3.3.0, firmware `V2.1.01-200817`, and the appliance-documented read-only `mib all` configd dump. The device permits only one Telnet session; concurrent attempts close before `login:`.
- Real Docker E2E passed through the new path: OpenWrt seed authentication → Cirotech discovery/revalidation → Telnet pull (49,168 characters / 1,042 lines) → Config persistence → Celery dispatch. Config `3dbb5dab-62ef-480d-9595-841192566def` reached `awaiting_training` with 1,041 source-backed findings. This is expected for the first audit of a proprietary unsupported MIB: the generic normalizer did not discard syntax or allow unapproved evidence into deterministic compliance. Completing its first compliance report requires operator-approved mappings; later Cirotech audits reuse those vendor-scoped mappings.
- Added mandatory demo instructions at `docs/DEMO_SETUP.md`: cable/interface mapping, fresh-session temporary bridge setup and restoration, router reachability/login checks, optional RAM-only LLDP setup, Compose startup, exact UI flow, expected audit state, and emergency recovery. README links to it.
- Discovery evidence does not automatically identify the Cirotech product vendor: ARP/neighbor tables provide address, MAC, and interface. For the known physical demo device, the operator selects the fixed Cirotech profile; LLDP vendor hints are used only when an actual advertisement supplies them. The runbook calls this out to avoid presenting MAC evidence as a vendor identity.
- The runbook states that the first Cirotech audit will normally remain in training until mappings are approved; this may not produce a completed compliance PDF during a short demo. It includes the verified OpenWrt `.2` and Cirotech `.1` addresses and warns against reset/upgrade or persistent router package/config changes.

## Persistent discovery orchestration and Ollama queue hardening (13 September 2026)

- Added persistent `DiscoverySession → DiscoveredDevice → Config` records and migration `d7a4b92f13c8`. The API runs bounded breadth-first traversal with address deduplication, depth/device limits, resolve-then-pin validation, and per-device failure isolation. It uses fixed Cisco CDP/LLDP, Juniper LLDP, or Linux/OpenWrt LLDP/kernel-neighbor commands; operators cannot supply discovery shell text.
- Advertised Cisco, Juniper, Fortinet, or OpenWrt neighbors may be pulled automatically only when the caller explicitly enables reuse of the request-local seed credentials. Passive ARP/kernel candidates remain `needs_input`: address/MAC/interface/evidence are retained, but Valsec does not assert that a host is a router or guess its vendor. The UI asks only for the missing fixed profile and credentials; the discovered IP is not re-entered. Passive laptop/host entries can be marked `skipped`.
- `POST /api/configs/discovery-sessions`, session GET, per-device process, and per-device skip endpoints are live. The earlier direct pull, discovery-evidence, revalidated pull, approved push, and audit APIs remain unchanged and available.
- Added fixed Cisco/Juniper discovery parsers with normalized evidence and retained the OpenWrt/Linux neighbor fallback. Added the correct fixed FortiOS SSH read command (`show full-configuration`) without changing normalization or compliance logic.
- Hardened local Ollama mapping requests for real device-sized queues. Unknown lines are prioritized by security relevance, capped at 96 candidates per audit, and split into 24-line structured batches; all non-selected or invalid lines remain available for manual review. A JSON schema asks Ollama for exactly one entry per input and the validator accepts only narrowly normalized scalar/list wrappers before enforcing the canonical field type. AI output is still advisory: valid proposals persist as `probable`, and only an operator can make them `confirmed`.
- Live Docker/hardware verification used OpenWrt `192.168.1.2` as the authenticated seed. It discovered Cirotech `192.168.1.1` with MAC `c4:70:0b:bc:19:30` through `neighbor_table + arp_table`, plus two passive laptop-side entries. Cirotech correctly paused for profile/credentials. Supplying the fixed Cirotech Telnet profile ran only `mib all`, created Config `b8e7d292-3ca6-4e1b-9463-aed88b5791b5`, linked it to the discovered-device record, and dispatched the existing Celery audit. The two non-router candidates were skipped and discovery session `54872792-da80-4f4f-8c40-6265200e32da` reached `complete`.
- The real Cirotech audit reached `awaiting_training` with 1,041 source-backed lines. Local `qwen2.5:7b` processed 96 prioritized candidates in four batches in 116.8 seconds and returned 8 validator-approved proposals. Those 8 are exposed as `probable`; the other lines remain `unverified`. No AI proposal was auto-approved and deterministic PASS/FAIL/N/A was not invoked while training remains outstanding.
- Verification: `python3 -m pytest tests -q` reports **266 passed**; the focused discovery/Ollama/training run reports **49 passed**. Backend compilation, `git diff --check`, Docker Compose validation, frontend typecheck, and Next.js production build all pass. Backend/worker/frontend images were rebuilt; PostgreSQL is at migration head `d7a4b92f13c8`; the live frontend and all four session endpoints respond.
- Updated `docs/ARCHITECTURE.md`, `README.md`, and `docs/DEMO_SETUP.md` to describe the persistent session flow. The morning runbook retains the exact bridge, cable, address, optional `/tmp` LLDP, login, service, and recovery steps for the physical pair.

### Current discovery limitations

- The OpenWrt/Cirotech case cannot safely be fully credential-free: ARP proves recent IP/MAC reachability only. The operator must provide the known Cirotech fixed profile and Telnet credentials once after discovery. Valsec never asks for Router 2's address again.
- Automatic credential reuse is suitable only when an actual CDP/LLDP advertisement identifies a supported profile and the neighbor shares the seed credentials. Authentication rejection moves that device to `needs_input` without aborting siblings.
- The discovery session is orchestrated synchronously because credentials are never persisted or placed in Celery. Hard limits bound the work, but a large standards-based topology can hold the HTTP request while fixed pull attempts complete.
- Manually completing a `needs_input` device does not launch another traversal hop in this pass. Multi-hop BFS works through automatically eligible advertised devices; extending traversal after manual credentials would require an explicit request-scoped continuation because secrets cannot be stored.
- The proprietary Cirotech dump is intentionally generic and produces a large human review queue on first contact. Ollama improves suggestions, but operator-approved mappings are still required before a report can complete.

### Exact next demo actions

1. Follow `docs/DEMO_SETUP.md` after reconnect/reboot and confirm both bridge-scoped pings.
2. Confirm `qwen2.5:7b` is visible at `http://127.0.0.1:11434/api/tags`, then start `docker compose -p valsec_final up -d` without deleting volumes.
3. Open `/configs/upload`, start **Discover & Audit Neighbors** with only the OpenWrt seed details, and identify the evidenced `.1` Cirotech row.
4. Enter the Cirotech Telnet fixed profile/credentials on that discovered row and click **Continue pull & audit**. Mark laptop-side passive candidates **Not a router**.
5. Open the linked audit and show that valid Ollama suggestions are `probable`, unmatched syntax is `unverified`, and operator approval remains required. Do not bulk-confirm unreviewed mappings.

## Post-cleanup repository audit (14 September 2026)

- Removed stale references to the deleted team-ownership document, submission ZIP, scanner-era database modules/settings, prototype frontend naming, and deleted sign-in/sign-up pages. Current reviewer ownership points to `.github/CODEOWNERS`.
- README links, documented source paths, sample configurations, migrations, frontend routes, API endpoints, framework coverage, and the OpenWrt/Cirotech demo flow were checked against the active Valsec-only tree.
- Added `httpx>=0.27,<1` to `backend/requirements-dev.txt`, the canonical CI/test dependency set required by FastAPI/Starlette `TestClient`.
- Verification passed for backend compilation, 265 non-HTTP-TestClient backend tests, `npm ci`, frontend typecheck, frontend production build, Docker Compose configuration, and `git diff --check`. The remaining HTTP `TestClient` test could not execute in the restricted local sandbox because its preinstalled Python 3.14 runtime cannot create the required stream file descriptor; CI uses Python 3.11 with the repository-pinned dependencies and now installs `httpx` explicitly.
- No tracked environment file, private key, generated runtime database/log, or credential was found. Local generated `.secret_key`, cache, bytecode, build, and dependency directories remain ignored.

## Device registry, drift, fleet summary, and observability (14 September 2026)

### What changed

- Added durable `Device` records and nullable `Config.device_id` links in Alembic revision `e2f6c8a41d90`. Uploads match vendor/display name; pulls and discovery reuse the resolve-then-pin address as the indexed identity. Existing response fields are unchanged and `device_id` is additive.
- Added owned device inventory/detail/update, immutable audit history, completed-audit baseline selection, pure deterministic drift, and latest-per-device fleet aggregation endpoints. Decommissioned devices remain queryable but are excluded from the summary.
- Added `/devices` and `/devices/[id]` frontend views plus typed API functions for every registry endpoint. The existing Valsec console views were not restructured.
- Added `/health` and `/ready`, removed hard-coded Celery concurrency, and added backend/worker/frontend Compose health checks. Ollama readiness checks only reach `/api/tags`; they never invoke inference or influence compliance.
- Added focused registry resolution, ownership, baseline, decommission, fixture-backed drift, latest-window fleet, health posture, and migration tests.

### What was verified

- All new focused tests pass in the local sandbox. The complete suite passes except for the previously documented sandbox-only AnyIO/TestClient stream-FD limitation.
- Backend/migration compilation, Alembic fresh-chain and downgrade SQL rendering, Docker Compose validation, frontend typecheck, frontend production build, and `git diff --check` pass.

### What remains

- Execute the migration upgrade/downgrade against fresh and retained PostgreSQL volumes and run the complete Python 3.11 suite in CI or an unrestricted container. The local environment exposes neither a PostgreSQL server nor the Docker daemon.

## P1-1 credential vault PR description (14 September 2026)

### Step 0: confirmed repository shapes

- `Device` already has nullable `org_id`; authenticated P0 ingestion and registry ownership use it as the current user UUID. There was no `owner_user_id`, so P1-1 reuses `org_id` and adds no duplicate ownership column. This deviates from the prompt's example name while preserving the actual model.
- Device resolution uses `resolve_device(db, *, vendor, os_type, display_name, org_id=None, management_address=None)`, `link_config_to_device(...)`, and `link_if_database_session(...)` in `backend/device_registry.py`.
- Registry ownership uses `get_owned_device_or_404(device_id, request, db)`. Routes are `/api/devices`, `/api/devices/{device_id}`, `/history`, `/baseline`, `/drift`, and `/api/fleet/summary`. List/history responses are item envelopes; detail returns the device payload directly.
- Deterministic drift uses `ControlDelta`, `DriftReport`, and `build_drift_report(...)`.
- The confirmed pre-P1-1 Alembic head was `e2f6c8a41d90`; credential revision `b3a7d1e94f20` chains directly from it.
- Celery concurrency remains `settings.MAX_CONCURRENT_AUDITS`; no `WORKER_CONCURRENCY` setting exists.

### What changed

- Added an opt-in pluggable secret backend and local Fernet implementation using a dedicated production-validated `CREDENTIAL_VAULT_KEY`. The default remains `ENABLE_CREDENTIAL_VAULT=false`, where every vault endpoint returns `404` before database/auth side effects.
- Added `DeviceCredential` and append-only `CredentialAccessLog` tables. Only encrypted opaque references are persisted. Metadata-only create/list/revoke endpoints never return plaintext or the opaque reference.
- Added optional direct-pull `use_stored_credential` plus `device_id`. Decryption is server-side and request-scoped, the existing SSH connector is reused unchanged, and successful connector use writes an access event best-effort with a warning on logging failure.
- No scheduling, Celery beat, Organizations/Sites/Roles, discovery stored-credential integration, AI call, compliance change, normalizer change, or remediation behavior change was introduced.

### Human security review required before hosted merge

The former `_require_local_device_access` boundary changed for direct pull and discovery: under `REQUIRE_AUTH=true`, those paths are no longer unconditionally disabled. P1-1 initially required the authenticated actor to match the raw `Device.org_id`; P1-3 supersedes that temporary equality with role-bearing Organization membership. The owner-claim and target-binding logic remains security-sensitive and requires explicit human review before any hosted/multi-user deployment. Remediation approval and PUSH deliberately retain the prior local-only restriction through `_require_local_remediation_access`.

### Verification and remaining environment checks

- The P1-1 vault/startup/CRUD/ownership/stored-pull/migration group reports **26 passed**. The complete locally runnable backend suite reports **304 passed, 1 deselected**; the sole deselection is the previously documented Python 3.14 sandbox AnyIO stream-FD limitation, while CI runs Python 3.11 with explicit `httpx`.
- Backend/migration compilation, offline PostgreSQL upgrade and `b3a7d1e94f20 → e2f6c8a41d90` downgrade SQL, Compose configuration, frontend typecheck, and `git diff --check` pass. The new Alembic head is `b3a7d1e94f20`.
- A live fresh-PostgreSQL `upgrade head` / `downgrade -1` remains for CI because the local environment exposes neither PostgreSQL nor the Docker daemon. The CI workflow now runs that exact credential-vault migration cycle against PostgreSQL 16.

## P1-3 organizations and membership roles (15 September 2026)

**Organization invariant: `Device.org_id` references a real `Organization`; an authenticated user's first claim lazily creates or reuses a personal Organization whose UUID equals that user's UUID and grants that user the `owner` membership, while unauthenticated local-mode devices remain `NULL`.**

### Step 0 findings

- Before this revision, `Device` had nullable UUID `org_id` with no FK and
  `User` exposed UUID `id`; no Organization or Membership model existed.
- `authorize_or_claim_device()` assigned `user.id` on a first network/vault
  access and rejected non-equality thereafter. `devices._owned_devices()` and
  `get_owned_device_or_404()` performed the corresponding inventory checks;
  credential routes delegated to `get_device_for_access()`.
- The prior invariant sentence and
  `test_org_id_is_the_stable_deterministic_claiming_user_id` both guaranteed
  that one user's devices shared that user's stable UUID and different users
  could not collide.
- `alembic heads` reported `b3a7d1e94f20` before implementation; P1-3 chains
  directly from that actual head.

Step 0 found that `Device.org_id` was the only `org_id` ownership boundary and
that raw equality was centralized in `device_ownership.py` and device inventory
queries. Credential routes delegated to that helper. Discovery sessions retain
their existing `user_id`; because personal Organization UUIDs preserve the
owner's User UUID, the session can be authorized through membership without a
second ownership column.

The roles follow the operations that were already ownership-gated:

`owner/operator/viewer` was chosen because the existing boundary naturally
separates member administration, state-changing device/network/credential
operations, and metadata/audit reads; it adds no speculative permission domain.

| Role | Existing ownership-gated device capabilities |
| --- | --- |
| `owner` | Read and modify devices, pull/process discovery, manage credentials, and add organization members |
| `operator` | Read and modify devices, pull/process discovery, and manage credentials |
| `viewer` | Read device inventory/history/drift and credential metadata only |

Personal Organizations are created lazily on first authenticated claim. The
minimal member endpoint accepts an already-registered `user_id`; it does not
create organizations, invitations, or accounts. Local `REQUIRE_AUTH=false`
behavior bypasses memberships and leaves `Device.org_id` NULL.

### Human migration review required

The `c8d2e5f71a40` revision is a **data-rewriting migration requiring human
security review before deployment**. Review its upgrade and downgrade mapping
specifically: each former raw `User.id` remains the personal
`Organization.id`, receives exactly one `owner` membership, and downgrades to
the original UUID losslessly. The identity-preserving mapping avoids device
reconciliation, while the DML uses conflict guards for idempotent retries.

The prior raw-equality test
`test_org_id_is_the_stable_deterministic_claiming_user_id` was replaced by
membership tests preserving its guarantee: one user's claims converge on one
exclusive deterministic personal Organization, distinct users do not collide,
and cross-organization access remains denied.

### Verification

- The current Alembic head is `c8d2e5f71a40` (chained from the Step 0 head
  `b3a7d1e94f20`). A disposable PostgreSQL 16 database was migrated from a
  fresh base through P1-1, seeded with two owners, three owned devices, and one
  local unowned device, upgraded through P1-3, and downgraded one revision.
  Upgrade produced exactly two personal Organizations and two owner
  Memberships with no orphaned device; downgrade restored all four `org_id`
  values exactly and removed both new tables and the role enum.
- Organization/role/migration-focused tests pass, including deterministic
  personal claims, local-mode no-op behavior, cross-org isolation, and a viewer
  added through the member endpoint who can read but cannot modify a device.
- The exact CI-runtime suite in an ephemeral Python 3.11 backend container
  reports **311 passed**. The host Python 3.14 run reports **310 passed, 1
  deselected** because of the previously documented AnyIO/TestClient stream-FD
  restriction; the container result confirms this is environment-only.
- `python3 -m compileall -q backend migrations`, `docker compose config -q`,
  frontend typecheck, the Node 20 containerized production build, Alembic head
  inspection, and `git diff --check` pass.

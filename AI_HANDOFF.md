# Valsec final engineering handoff

Updated: 13 September 2026 (Asia/Kolkata)

## Submission state

Valsec is a standalone network-device configuration compliance product. The prior web assessment product, its routes, task graph, data tables, Docker services, frontend pages, documentation, tools, tests, and assets have been removed from the active tree. PostgreSQL, Redis, Celery, FastAPI, local Ollama, WeasyPrint reporting, authentication/ownership primitives, and the Nimbus-derived Valsec frontend remain.

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

The database migration chain is now a clean Valsec baseline plus the existing compatibility head. The active ORM contains User, AuthProvider, Config, NormalizedFinding, LearnedMapping, ComplianceResult, and config-only Report entities.

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
- `TEAM_FILE_OWNERSHIP.md`
- Clean Valsec baseline migration and Valsec-only Docker/CI/runtime configuration.

See the Git diff for the complete removal list and all modified integration files.

## Remaining limitations

- Non-CIS framework catalogues are representative subsets, not complete certification content.
- Fortinet supports the implemented NIST catalogue; other Fortinet framework combinations return an explicit unsupported response.
- Generic-vendor onboarding can only evaluate controls supported by schema fields an operator has taught; it is not a hand-written vendor adapter.
- Ollama availability and output quality affect proposal/remediation convenience only. Manual training and deterministic results remain available.
- Optional hosted authentication APIs remain available, while the submission frontend is optimized for the default local single-operator demo and has no account-management screens.
- One moderate transitive frontend production advisory remains in `baseline-browser-mapping`; no high or critical production advisory remains.
- Device pull/push is deliberately disabled when `REQUIRE_AUTH=true`; it is a local single-operator feature rather than a hosted network pivot.
- Cisco applies running configuration only. Junos uses a five-minute confirmed commit. FortiOS has no automatic push procedure in this pass, and risky generic/UCI changes are always manual.
- First-contact SSH currently accepts the appliance host key for the ephemeral connector session. Operators should use a trusted management LAN; persistent fingerprint enrollment is a future hardening item.

## Local device pull and approved push (13 September 2026)

- Added a resolve-then-pin SSH target guard. Private, public, and ordinary link-local device addresses are accepted; loopback, IPv4-mapped loopback, and `169.254.169.254` are blocked.
- `POST /api/configs/pull-device` runs exactly one fixed read command (`show running-config`, Junos display-set, or `uci show`), stores no credentials, creates a normal queued `Config`, and dispatches the existing audit task. Connector failures create no Config row.
- Added `RemediationAction` and migration `c4e8a2f91b76`. Approval copies existing `ComplianceResult.remediation_cli` once; the apply endpoint accepts no command text and passes only the stored approval to the connector.
- Cisco push enters configuration mode and never sends `write memory` or a startup-copy command. Junos sends `commit confirmed 5`, re-pulls to verify reachability, and only then sends the final commit. A failed re-pull leaves the device to auto-rollback and reports that state.
- Generic/UCI push accepts only a narrow UCI mutation grammar, commits and uses fixed reload commands. Session-affecting UCI changes are refused even when the caller sets risky confirmation. FortiOS automatic push is explicitly unsupported.
- Every successful apply stores pre/post snapshots and a unified diff. The results API and Nimbus UI expose approval/apply state and diff evidence. SSH passwords remain only in `SecretStr` request objects and connector call memory.
- New focused tests: target guard, SSH pull, risk classification, SSH push, pull router, and push router. The complete active backend suite reports **243 passed**; the focused connector/router group reports **48 passed**. Frontend typecheck and production build pass.
- Docker images rebuilt, Alembic upgraded both the retained database and a disposable fresh PostgreSQL database through `base → f8c2a9d4e761 → 9b4f1d7e2c30 → c4e8a2f91b76`, backend/worker/frontend started, and all three new API paths appeared in the live OpenAPI schema. A real read-only pull from the supplied Dropbear/OpenWrt device succeeded, stored 7,307 characters, and queued Config `7e919f1b-e865-46a8-91b6-8a74da6c34cc`. The existing Ollama request timed out cleanly after its bounded retries, so the audit reached `awaiting_training` with 227 source-backed unverified lines. Paramiko 4 is pinned because this appliance offers only an `ssh-rsa` host key; modern algorithms remain preferred. No live remediation was pushed.

## Exact next human actions

1. Review the working-tree diff, especially the deliberate removal of the old product and rewritten clean baseline migration.
2. Copy `.env.example` to `.env`, set strong production secrets if exposing the service, and confirm `qwen2.5:7b` is installed in local Ollama.
3. Use `backend/tests/sample_configs/mixed_vendor_fleet.zip`; provide vendor hint `unknown.conf = NewCo NOS` in the UI to demonstrate the learning gate.
4. Open `/home/aayush-yadav/Valsec_Final.zip`, review `TEAM_FILE_OWNERSHIP.md`, and distribute it to the team.
5. If scope continues after submission, expand the representative NIST/DISA/ISO catalogues with reviewed authoritative control mappings and vendor evidence tests.

## Seed neighbor discovery and Cirotech Telnet pull (13 September 2026)

- Added modular authenticated discovery in `backend/connectors/neighbor_discovery.py`. It prefers LLDP management data when advertised and merges it with valid `ip neigh` and `/proc/net/arp` entries. Kernel entries are candidates, not asserted router identities.
- Added `POST /api/configs/discover-neighbors` and `POST /api/configs/pull-discovered-device`. The pull endpoint repeats discovery before connection, then uses the existing Config persistence, Celery dispatch, normalization, training, compliance, and report lifecycle.
- Added a constrained Cirotech Linux-shell Telnet connector. It permits only private/link-local pinned targets, accepts no operator command text, runs the appliance-documented read-only `mib all` configd dump, bounds output to 5 MiB, sanitizes failures, closes sessions, and never persists credentials. It never invokes the separate `mib commit` write operation. Telnet is plaintext and is intended only for the isolated management LAN.
- Added the Nimbus-compatible **Discover & Audit Neighbor** UI. The operator authenticates to the seed, selects from returned evidence, supplies that neighbor's credentials, and enters the existing status/training/results views.
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

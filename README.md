# Valsec

Valsec is a local-first network-device configuration compliance auditor built for SIH 2026 (SIH26155). It normalizes Cisco IOS/IOS-XE, Juniper JunOS, and Fortinet FortiOS configurations into one vendor-neutral schema, evaluates deterministic framework rules, generates vendor CLI remediation, and produces a Valsec PDF report.

Valsec supports routers, switches, and firewalls through Cisco, Juniper, and Fortinet adapters. An unsupported vendor can be onboarded without a parser: Valsec preserves its vendor identifier, proposes schema mappings with local Ollama, requires operator approval, and reuses approved mappings only for the same user and vendor.

AI can propose schema mappings and remediation text. It cannot determine PASS, FAIL, N/A, severity, or score.

## Capabilities

- Single-file, multi-file, and safe ZIP ingestion, with an independent audit per device.
- Per-file detection for mixed Cisco, Juniper, Fortinet, and unknown-vendor batches.
- ZIP traversal checks, member/count/size limits, filename validation, and ownership checks.
- Source-backed normalization with `confirmed`, `probable`, and `unverified` confidence.
- Human approval gate before proposed mappings become `confirmed`.
- Persistent mappings isolated by authenticated user and vendor.
- Deterministic CIS Cisco IOS (23 controls), CIS Juniper (11 controls), NIST SP 800-53 Rev. 5 (8 neutral controls and 7 Fortinet controls), DISA Network Device STIG V1R1 (6 controls), and ISO/IEC 27001:2022 Annex A (6 controls).
- Deterministic Cisco, Juniper, and FortiOS remediation where a template exists; validated local Ollama fallback is explicitly marked for review.
- Valsec-branded PDF with device identity, framework, score, verdicts, severity, evidence, requirements, and remediation.
- Nimbus-derived dashboard connected to the real FastAPI endpoints.
- Local SSH pull and authenticated seed-based neighbor discovery into the existing audit lifecycle, using fixed read-only commands and resolve-then-pin target validation.
- Operator-approved remediation push with Cisco running-config-only application, Junos confirmed commits, post-change re-pull, and a visible configuration diff.
- Persistent breadth-first discovery sessions using CDP/LLDP where present and kernel neighbor/ARP evidence as a passive fallback. Eligible advertised neighbors can be processed automatically; evidence-only candidates pause for their missing fixed profile and credentials before entering the existing audit pipeline.

The non-CIS catalogues are representative technical control mappings for a demonstration. They are not full certification or accreditation coverage.

## Start with Docker

Requirements: Docker Compose and a local Ollama service with `qwen2.5:7b` when AI proposals are desired.

```bash
cp .env.example .env
docker compose up -d --build
```

Open `http://localhost:3000`. FastAPI is at `http://localhost:8000`; PostgreSQL is bound to localhost port 5432 and Redis to localhost port 6380. Ollama is reached through `host.docker.internal:11434` by default. If Ollama is unavailable, audits still enter manual training.

For any exposed or authenticated deployment, replace `POSTGRES_PASSWORD` and `SECRET_KEY`, set `VALSEC_ENV=production`, use TLS, and configure the allowed origin and cookie settings.

## API

- `POST /api/configs/upload` — raw text, one file, multiple files, or ZIP; accepts framework, fallback vendor, and optional per-file vendor hints.
- `GET /api/configs` — fleet/audit list.
- `GET /api/configs/{id}/status` — lifecycle and pending review count.
- `GET /api/configs/{id}/results` — deterministic compliance results and remediation.
- `GET /api/configs/{id}/report` — authorized PDF download.
- `GET /api/configs/{id}/unverified` — unverified/probable lines and any validated AI proposal.
- `POST /api/configs/{id}/train` — approve a mapping and resume once all findings are confirmed.
- `POST /api/configs/pull-device` — fetch a LAN device configuration over SSH and queue it through the same audit pipeline as an upload.
- `POST /api/configs/discover-neighbors` — authenticate to a seed and return LLDP/kernel-neighbor evidence without scanning the subnet.
- `POST /api/configs/pull-discovered-device` — revalidate a selected discovered address, pull through a fixed SSH or Cirotech Telnet profile, and queue the existing audit.
- `POST /api/configs/discovery-sessions` — persist a bounded BFS session and automatically process eligible advertised neighbors.
- `GET /api/configs/discovery-sessions/{id}` — return discovered devices, linked Config IDs, and live audit states.
- `POST /api/configs/discovery-sessions/{id}/devices/{device_id}/process` — supply a passive candidate's missing fixed profile/credentials, then reuse normal pull/audit ingestion.
- `POST /api/configs/discovery-sessions/{id}/devices/{device_id}/skip` — mark passive host evidence as not a router for this session.
- `POST /api/configs/{id}/findings/{finding_id}/approve-remediation` — freeze the existing remediation text after operator review.
- `POST /api/configs/{id}/findings/{finding_id}/apply-remediation` — apply only that approved text and return before/after snapshots and a unified diff.

Device SSH endpoints are available only in local single-operator mode and return `403` when `REQUIRE_AUTH=true`. SSH passwords are request-only and are never stored. Cisco push changes running configuration only; startup persistence remains a separate manual action. Junos uses `commit confirmed 5`, verifies reachability, then commits permanently. Risky generic/UCI changes are always refused because no automatic rollback is available.

Lifecycle: `queued → normalising → awaiting_training → compliance_check → complete`. Dispatch or processing errors become `failed` and are surfaced in the API/logs.

## Native development and focused tests

```bash
python3 -m pip install -r backend/requirements.txt -r backend/requirements-dev.txt
cd backend
python3 -m pytest tests -q
python3 -m compileall -q . ../migrations

cd ../frontend
npm ci
npm run typecheck
npm run build

cd ..
docker compose config
```

The retained tests are Valsec tests. Scanner-specific test modules and tooling are not part of this repository.

## Demo flow

1. Upload the hardened and vulnerable Cisco samples from `backend/tests/sample_configs/`.
2. Upload Juniper and Fortinet samples, or select them together with Cisco in one multipart batch.
3. Upload unknown syntax with a stable vendor hint. A valid Ollama proposal appears as `probable`; otherwise it remains `unverified`.
4. Approve the mapping in Training. The audit resumes through deterministic evaluation, remediation, and PDF generation.
5. Upload the same syntax for the same vendor again to demonstrate confirmed learned-mapping reuse.
6. For a direct LAN audit, use **Pull Configuration**. For the validated OpenWrt/Cirotech neighbor demo, follow [the two-router discovery runbook](docs/DEMO_SETUP.md): it recreates the temporary Ubuntu bridge, starts one persisted discovery session, discovers Cirotech from OpenWrt's kernel neighbor evidence, asks only for the missing Cirotech profile/credentials, and pulls its read-only `mib all` dump. The operator never re-enters Router 2's address.
7. For a failed finding on an SSH-supported device, review and approve its exact remediation, enter request-only SSH credentials, apply it, and inspect the returned before/after diff. Risky changes require care and recovery access.

See [AI_HANDOFF.md](AI_HANDOFF.md) for verified results and limitations and [TEAM_FILE_OWNERSHIP.md](TEAM_FILE_OWNERSHIP.md) for team ownership.

# Valsec

Valsec is an air-gapped network-device configuration compliance auditor for
Smart India Hackathon 2026 problem SIH26155. It normalizes Cisco IOS/IOS-XE and
Juniper JunOS configurations into a shared schema, evaluates compliance with a
deterministic rule engine, produces vendor CLI remediation, and generates a
downloadable Valsec compliance PDF.

Unknown syntax is never discarded. Valsec first checks operator-approved learned
mappings, then asks a local Ollama model for a reviewable proposal, and pauses the
audit until an operator approves the mapping. AI cannot set or change a verdict,
severity, or compliance score.

## Implemented scope

- Cisco IOS/IOS-XE and Juniper JunOS adapters with source-line provenance.
- Single configuration, multiple multipart files, and ZIP fleet ingestion. Each
  configuration gets an independent database lifecycle and Celery task.
- Deterministic catalogues for:
  - CIS Cisco IOS Benchmark: 23 controls.
  - CIS Juniper JunOS Benchmark: 11 representative controls.
  - NIST SP 800-53 Rev. 5: 8 representative controls.
  - DISA Network Device STIG V1R1: 6 representative controls.
  - ISO/IEC 27001:2022 Annex A: 6 representative controls.
- `queued → normalising → awaiting_training → compliance_check → complete`
  asynchronous audit lifecycle.
- Local Ollama mapping proposals, explicit operator approval, persistent learned
  mappings, and later reuse isolated by user and vendor.
- Deterministic Cisco and Juniper remediation templates. A missing template may
  use a validated local Ollama configuration block marked as AI generated and
  requiring operator review.
- Nimbus-based Valsec dashboard, upload, fleet list, training queue, results,
  remediation, and PDF download backed by real APIs.
- Optional account/session ownership enforcement when `REQUIRE_AUTH=true`.

The NIST, DISA, ISO, and Juniper CIS catalogues are working representative
catalogues for the SIH demonstration. They are not full certification packs.

## Architecture

```mermaid
flowchart LR
    UI[Next.js Valsec UI] --> API[FastAPI config APIs]
    API --> PG[(PostgreSQL)]
    API --> Q[Redis / Celery]
    Q --> V{Vendor adapter}
    V --> C[Cisco IOS]
    V --> J[Juniper JunOS]
    C --> S[Vendor-neutral schema]
    J --> S
    S -->|unknown syntax| L[User/vendor mapping lookup]
    L --> O[Local Ollama proposal]
    O --> T[Operator approval]
    T --> PG
    S --> D[Deterministic framework engine]
    D --> R[Vendor remediation]
    R --> P[Valsec PDF]
    P --> PG
```

Compliance catalogues consume only the typed neutral schema. AI and training
live outside the verdict path. Adding another vendor requires an isolated parser
and remediation adapter; adding another framework requires a rule catalogue.

## Prerequisites

- Docker with Docker Compose v2
- Ollama with `qwen2.5:7b` for AI proposals and fallback remediation
- Python 3.11+ and Node.js 20+ when running services outside Docker
- WeasyPrint system libraries when running the backend directly

Prepare local Ollama:

```bash
ollama pull qwen2.5:7b
ollama serve
```

Ollama is optional for deterministic audits. When it is unavailable, unknown
syntax still enters manual training and missing remediation remains explicitly
unavailable.

## Docker setup

Set deployment secrets, build the stack, and run migrations through the backend
startup command:

```bash
export POSTGRES_PASSWORD='replace-with-a-strong-password'
export SECRET_KEY='replace-with-a-long-random-secret'
docker compose up -d --build postgres redis zap backend worker frontend
docker compose ps
```

Open <http://localhost:3000>. FastAPI is available at
<http://127.0.0.1:8000>; development API documentation is at
<http://127.0.0.1:8000/docs>.

The full Compose graph retains the earlier web-scanner services and therefore
builds a larger backend image and starts ZAP. For a focused native Valsec setup,
start only PostgreSQL and Redis, then run the API, worker, and frontend from the
checkout:

```bash
docker compose up -d postgres redis
export DATABASE_URL=postgresql://vapt:${POSTGRES_PASSWORD}@127.0.0.1:5432/vapt
export REDIS_URL=redis://127.0.0.1:6380/0
export OLLAMA_URL=http://127.0.0.1:11434
alembic upgrade head

# terminal 1
cd backend
uvicorn main:app --host 127.0.0.1 --port 8000

# terminal 2, from backend/
celery -A tasks.celery_app worker --loglevel=info -c 1

# terminal 3, from frontend/
npm ci
npm run build
npm run start
```

The native frontend listens on <http://localhost:3002> and rewrites `/api/*` to
the backend at port 8000.

## Demo configurations

Curated fixtures are in [`backend/tests/sample_configs`](backend/tests/sample_configs):

| File | Expected behavior |
|---|---|
| `cisco_hardened.cfg` | Cisco CIS completes at 100%: 21 PASS, 0 FAIL, 2 N/A |
| `cisco_vulnerable.cfg` | Completes with deterministic failures and Cisco CLI remediation |
| `cisco_unseen_syntax.cfg` | Pauses for mapping approval, resumes, and reuses the learned mapping later |
| `juniper_hardened.conf` | Juniper CIS completes at 100%: 11 PASS, 0 FAIL, 0 N/A |

Upload one configuration:

```bash
curl -F file=@backend/tests/sample_configs/cisco_hardened.cfg \
  -F vendor=cisco \
  -F framework=cis_cisco_ios_v1 \
  -F device_name=valsec-hardened \
  http://127.0.0.1:8000/api/configs/upload
```

For Juniper, set `vendor=juniper`. Supported framework keys are
`cis_cisco_ios_v1`, `nist_sp_800_53_rev5`, `disa_stig_network_v1`, and
`iso_iec_27001_2022`.

A ZIP may contain up to 50 `.cfg`, `.conf`, or `.txt` members. Its response has a
`configs` array with one ID per member. Poll every ID independently. The selected
vendor and framework apply to all members in one upload batch.

For the training demo:

```bash
curl http://127.0.0.1:8000/api/configs/CONFIG_ID/status
curl http://127.0.0.1:8000/api/configs/CONFIG_ID/unverified

curl -X POST -H 'Content-Type: application/json' \
  -d '{"finding_id":"FINDING_ID","approved_schema_field":"ssh.version","approved_value":2}' \
  http://127.0.0.1:8000/api/configs/CONFIG_ID/train
```

After completion, upload the same unseen syntax again. The later audit should use
the confirmed mapping without entering `awaiting_training`.

## Config API

- `POST /api/configs/upload`
- `GET /api/configs`
- `GET /api/configs/{id}/status`
- `GET /api/configs/{id}/unverified`
- `POST /api/configs/{id}/train`
- `GET /api/configs/{id}/results`
- `GET /api/configs/{id}/report`

Upload safeguards are 5 MiB per plain configuration/member, 10 MiB compressed
per ZIP, 25 MiB expanded per request, and 50 configurations per request. ZIP
members are decoded in memory and never extracted to the filesystem.

## Focused validation

Install development dependencies, then run only the Valsec suites:

```bash
python3 -m pip install -r backend/requirements-dev.txt
python3 -m pytest \
  backend/tests/test_demo_configs.py \
  backend/tests/test_config_router.py \
  backend/tests/test_audit_orchestrator.py \
  backend/tests/test_training.py \
  backend/tests/test_training_integration.py \
  backend/tests/test_cisco_ios_normalizer.py \
  backend/tests/test_juniper_normalizer.py \
  backend/tests/test_cis_engine.py \
  backend/tests/test_frameworks.py \
  backend/tests/test_remediation_generator.py \
  backend/tests/test_valsec_hardening.py -q

cd frontend
npm ci
npm run typecheck
npm run build
```

## Security and deployment notes

- Configurations may contain credentials. Valsec stores raw configuration and
  source-backed findings in PostgreSQL for audit traceability. Protect the
  database, backups, and logs accordingly.
- Local mode is intentionally single operator and unauthenticated. Bind it to a
  trusted interface only. For shared use, set `REQUIRE_AUTH=true`, configure a
  strong `SECRET_KEY` and database password, use TLS-secure cookies, and set exact
  CORS origins. Production startup checks reject shipped placeholder secrets.
- Fleet list, status, training, results, and report access use the same owner
  boundary. Cross-owner IDs return 404 when authentication is enabled.
- Learned mappings use separate uniqueness scopes for authenticated users and the
  local single-operator mode, always including the vendor.
- ZIP traversal, encrypted archives, invalid extensions/encoding, oversized
  members, archive expansion, excessive member count, and invalid device names
  are rejected before audit creation.
- Ollama endpoints are restricted to loopback or recognized local Docker hosts.
  Prompt content is treated as untrusted JSON, outputs are schema validated, and
  generated CLI always carries an operator-review marker.
- A PostgreSQL advisory lock prevents duplicate tasks for one audit from mutating
  findings/results concurrently. Training uses row locks and database uniqueness;
  a broker dispatch failure restores a retryable `awaiting_training` state and
  returns HTTP 503 instead of claiming success.
- Compliance PDFs include evidence and remediation, but not the complete raw
  uploaded configuration.

## Known limitations

- The representative Juniper and NIST/DISA/ISO catalogues are demonstration
  coverage, not complete benchmark or certification content.
- A batch has one selected vendor and framework. Mixed-vendor archives require
  separate uploads.
- Fortinet, Palo Alto, and Arista have parser/remediation extension points but no
  implemented adapters.
- AI remediation is reviewable fallback text and may be incomplete or invalid for
  a particular firmware release; it is never applied automatically.
- Training dispatch recovery is request-driven rather than a durable outbox. If
  the broker fails, retry the same training submission after Redis recovers.
- The Docker database/user names retain historical `vapt` identifiers for
  migration compatibility. Change the shipped password before shared deployment.
- The retained legacy scanner increases the full Docker image size and emits
  unrelated dependency warnings; it is outside the Valsec demo path.

## Retained legacy scanner

The earlier authorized web-scanner implementation remains under `/scan/*` and
`/scans`, along with its report/UI components. It is preserved as reusable
infrastructure and is separate from Valsec config audits. See
[`ARCHITECTURE.md`](ARCHITECTURE.md) and [`docs/`](docs/) for that subsystem.

## Stop services

```bash
docker compose down
```

## License

MIT — see [`LICENSE`](LICENSE).

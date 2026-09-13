# Valsec team file ownership

Ownership follows the team engineering role specification. Cross-layer changes require the primary owner and each affected interface owner to review.

## Aayush — Normalisation Engine

| Path | Responsibility |
| --- | --- |
| `backend/normalizer/` | Vendor-neutral schema and all normalization adapters. |
| `backend/normalizer/cisco_ios.py` | Cisco IOS/IOS-XE parsing and provenance. |
| `backend/normalizer/juniper.py` | Juniper JunOS parsing and provenance. |
| `backend/normalizer/fortios.py` | Fortinet FortiOS parsing and provenance. |
| `backend/normalizer/generic.py` | Unsupported-vendor unknown-line preservation. |
| `backend/tests/test_*_normalizer.py` | Normalizer regressions. |
| `backend/tests/sample_configs/` | Cisco, Juniper, Fortinet, unknown, and mixed-fleet fixtures. |

## Kaustubh — Compliance Engine, Rule Tables, and Remediation

| Path | Responsibility |
| --- | --- |
| `backend/compliance/` | Deterministic evaluation, score, CIS rules, and modular catalogues. |
| `backend/compliance/catalogues.py` | CIS, NIST, DISA STIG, ISO, and supported-combination metadata. |
| `backend/remediation/` | Deterministic-template-first remediation service. |
| `backend/remediation/{cisco_remediation,juniper_remediation,fortios_remediation}.py` | Vendor CLI templates. |
| `backend/tests/test_cis_engine.py` | Cisco CIS and timeout regressions. |
| `backend/tests/test_frameworks.py` | Framework catalogue and combination tests. |
| `backend/tests/test_remediation_generator.py` | Vendor templates and marked AI fallback. |

## Parth — Interactive Training and Audit Lifecycle

| Path | Responsibility |
| --- | --- |
| `backend/training/` | Matching, signatures, reuse, and schema-field validation. |
| `backend/routers/training.py` | Training queue, ownership, duplicate-safe approval, and resume dispatch. |
| `backend/tasks/audit_orchestrator.py` | Normalization, proposal gate, deterministic evaluation, remediation, report, and lifecycle states. |
| `backend/tasks/celery_app.py` | Audit task registration; deployment changes are shared with Prakhya. |
| `backend/routers/device_access.py` | Local pull, immutable remediation approval, apply lifecycle, and API failure states; data-model review is shared with Abhijeet. |
| `backend/tests/test_device_{pull,push}_router.py` | Pull/push API, approval state, risky confirmation, and local-only security. |
| `backend/tests/test_training.py` | Ollama response and matcher tests. |
| `backend/tests/test_training_integration.py` | Persistence, isolation, concurrency, and reuse. |
| `backend/tests/test_audit_orchestrator.py` | Lifecycle and independent-device orchestration. |

## Abhijeet — Reporting and Data Layer

| Path | Responsibility |
| --- | --- |
| `backend/models.py`, `backend/database.py` | Valsec entities, constraints, ownership, and sessions. |
| `migrations/` and `alembic.ini` | Clean Valsec baseline and compatibility head. |
| `migrations/versions/c4e8a2f91b76_add_remediation_actions.py` | Approved remediation state, snapshots, and diff evidence. |
| `backend/reports/` | Compliance PDF generator and Valsec template. |
| `backend/routers/configs.py` | Upload/ZIP, fleet/status/results/report APIs, validation, and authorization. |
| `backend/main.py` | FastAPI assembly; shared with Parth and Prakhya. |
| `backend/tests/test_config_router.py` | Upload, mixed batch, ZIP security, APIs, and authorization. |
| `backend/tests/test_valsec_hardening.py` | Ownership, report content, and cross-layer security. |

## Prakhya — AI Integration and DevOps

| Path | Responsibility |
| --- | --- |
| `backend/analysis/ollama_client.py` | Local-only structured proposals, validation, prompt boundary, and fallback. |
| `backend/config.py`, `backend/security.py`, `backend/oauth.py`, `backend/email_service.py` | Runtime and authentication security. |
| `backend/Dockerfile`, `docker-compose*.yml`, `.env.example` | PostgreSQL, Redis, API, worker, frontend, and host Ollama deployment. |
| `backend/requirements*.txt` | Backend runtime and test dependencies. |
| `backend/connectors/` | Resolve-and-pin target guard, Paramiko transport, safe vendor apply procedures, and risk classifier; lifecycle review is shared with Parth. |
| `backend/tests/test_{target_guard,ssh_pull,ssh_push,risk_classifier}.py` | Connector boundary, command sequencing, rollback, and credential-sanitization tests. |
| `.github/workflows/` | CI validation. |

## Bhoomika — Frontend Dashboard and Delivery

| Path | Responsibility |
| --- | --- |
| `frontend/` | Final Nimbus-derived dashboard and production delivery. |
| `frontend/app/` | Dashboard, fleet, upload, status, training, frameworks, and report routes. |
| `frontend/components/valsec-console.tsx` | Valsec UI workflows and state presentation. |
| `frontend/lib/valsec-api.ts` | Typed real-backend API client. |
| `frontend/Dockerfile`, `frontend/next.config.mjs`, `frontend/package*.json` | Frontend build and API proxy. |
| `README.md` | Setup and demo delivery, reviewed by affected technical owners. |

## Shared review

| Path | Reviewers | Responsibility |
| --- | --- | --- |
| `AI_HANDOFF.md` | All owners | Verified current state, evidence, and limitations. |
| `TEAM_FILE_OWNERSHIP.md` | All owners | Ownership and review boundaries. |
| `docs/` | All owners | Architecture and security documentation. |
| `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md` | All owners | Project governance. |
| `.github/`, `.gitignore`, `.dockerignore` | Prakhya plus affected owner | CI and distribution hygiene. |

The final distribution contains the active Valsec sources, focused tests, fixtures, migrations, deployment files, and documentation. It excludes repository history, generated artifacts, local secrets, prototypes, automation logs, and the removed web-scanner product.

# AGENTS.md

## Project identity

Clinical Data Studio is a local-first and AWS Lightsail-ready electronic data capture system for small clinical research projects. It supports metadata-driven CRFs, participant/event data entry, review queries, audit trails, exports, backups, optional offline drafts, and explicitly gated academic AI workflows.

The primary objective is **reliable, auditable, privacy-preserving clinical research data capture**. Convenience features must not weaken data integrity, participant privacy, access control, auditability, backup/restore reliability, or study governance.

## Read first

Before editing, inspect:

1. this file
2. `README.md`
3. the files and tests that own the changed behavior
4. `.agents/skills/robust-repo-change/SKILL.md`
5. `.agents/skills/clinical-software-safety/SKILL.md`
6. other task-specific skills under `.agents/skills/`
7. `.github/workflows/ci.yml`

Repository code, schema, tests, and deployment documents remain authoritative. Shared skills supplement these local rules; they do not override them.

## Non-negotiable clinical-data rules

- Never commit patient or participant identifiers, real reports, images, audio, exports, databases, backup archives, screenshots, credentials, API keys, session cookies, access tokens, or production logs.
- Use synthetic or explicitly de-identified fixtures only.
- External AI remains disabled by default. Do not bypass project AI policy, PHI blocking, multimodal blocking, de-identification preview, or audit controls.
- A ChatGPT subscription is not local application API access. Never hard-code an API key or silently enable external processing.
- Preserve named-user access, least privilege, CSRF protection, login lockout, data-access groups, audit events, record locks/freezes, query history, and token revocation.
- Protect CSV/Excel exports from formula injection and accidental identifier leakage.
- Preserve uploads outside the database where the current storage design requires it; do not move binary evidence into database rows without an explicit migration and threat review.
- Do not place the live SQLite database in synchronized storage or use GitHub Pages/Drive as the live backend.
- Do not claim FDA 21 CFR Part 11, HIPAA, GCP, sponsor-validation, or production compliance without documented validation and governance evidence.

## Architectural ownership

- `server.py` owns application routing, request handling, command entry points, and high-level orchestration.
- `storage.py` owns persistence behavior, schema/migrations, audit persistence, and backend-specific data access.
- `config.py` owns environment/configuration parsing and safe defaults.
- `static/` owns the browser/PWA interface and offline-draft behavior.
- `tests/` and `.github/workflows/ci.yml` define the executable regression contract.
- Deployment files own Docker, Compose, Nginx/Lightsail, and production configuration behavior.

Do not create parallel persistence layers, duplicate authorization paths, hidden AI routes, or alternate audit mechanisms. Extend the existing owner.

## Change workflow

1. Define intended behavior, data touched, trust boundaries, and files that should not change.
2. Reproduce the defect or add a focused regression test through the real interface.
3. Establish root cause before editing.
4. Make the smallest owner-consistent change.
5. Test normal, malformed, unauthorized, offline/reconnect, and privacy-failure paths relevant to the change.
6. Review the diff for new data flows, logging, exports, caches, external calls, permissions, and migration impact.
7. Run the required validation on the final branch head.
8. Open one focused PR; resolve review comments; merge only after final CI succeeds.

## Minimum validation

Run the repository's CI-equivalent commands for affected areas. The baseline is:

```bash
python -m py_compile server.py config.py storage.py cds/db/migrations.py
node --check static/app.js
python -W error::ResourceWarning -m unittest discover -s tests
python server.py migrate
python server.py healthcheck
docker build -t clinical-data-studio:ci .
docker compose -f docker-compose.local.yml config
```

For persistence changes, validate both SQLite and PostgreSQL behavior and migrations. For browser/PWA changes, run the browser smoke test and relevant offline/conflict tests. For deployment changes, validate Docker/Compose and documented rollback/restore behavior.

## Release evidence

A change is not complete because the code looks plausible. Completion requires current test or CI evidence on the final PR head, an accurate summary of data/security impact, and explicit residual risk. Record durable decisions and validation in a `session-worklog` when work will continue in another chat.

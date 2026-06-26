# GitHub Copilot instructions — Clinical Data Studio

Read `AGENTS.md` before proposing or applying changes.

## Required behavior

- Preserve the existing architecture and change the owning module rather than adding parallel paths.
- Use `.agents/skills/robust-repo-change/SKILL.md` for debugging, features, refactors, PRs, CI failures, and deployment changes.
- Use `.agents/skills/clinical-software-safety/SKILL.md` whenever a change touches clinical/research data, identifiers, reports, uploads, exports, logs, audit trails, authentication, authorization, offline storage, backups, or external AI.
- Use `.agents/skills/research-protocol-publication/SKILL.md` for CRF design, study metadata, reporting-guideline, protocol, questionnaire, or academic-workbench requirements.
- Use `.agents/skills/artifact-production-qa/SKILL.md` for generated validation packages, spreadsheets, PDFs, Word files, or presentation outputs.
- Use `.agents/skills/session-worklog/SKILL.md` to preserve durable decisions after substantial work.

## Hard constraints

- Never add real patient/participant data, credentials, tokens, cookies, screenshots, production logs, database files, or backup archives.
- Keep external AI disabled by default and preserve policy, PHI, multimodal, de-identification, and audit gates.
- Do not weaken named-user access, CSRF, login lockout, data-access groups, record locking/freezing, auditability, export safety, backup verification, or restore behavior.
- Do not claim regulatory compliance or production validation without evidence.
- Add regression tests and use the commands in `AGENTS.md` and `.github/workflows/ci.yml` before claiming completion.

When requirements conflict, clinical-data safety and repository-local rules take precedence over generic coding convenience.

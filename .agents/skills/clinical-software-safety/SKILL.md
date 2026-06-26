---
name: clinical-software-safety
description: Design, review, test, and release software that handles clinical records, laboratory reports, research data, medical summaries, or AI-assisted clinical workflows while preserving privacy, provenance, auditability, deterministic behavior, and clinician verification.
---

# Clinical Software Safety

## Purpose

Prevent software convenience from weakening patient privacy, source fidelity, clinical verification, security, or research governance. Apply this skill to EDC systems, hospital-report parsers, clinical browser extensions, mobile clinical tools, decision-support features, and external-AI integrations.

## Workflow

### 1. Define intended use and prohibited use

Document:

- intended users and clinical/research setting
- whether the product stores, transmits, transforms, summarizes, or interprets clinical data
- whether output is administrative, research, descriptive, or decision-supporting
- decisions the software must never make autonomously
- environments and workflows that are explicitly unsupported

Do not describe an unvalidated tool as diagnostic, treatment-directing, regulatory-compliant, or production-safe.

### 2. Classify data and trust boundaries

Map every data path:

- source system, browser, device, server, database, backup, export, logs, telemetry, and external AI
- identifiers, quasi-identifiers, free text, images, audio, PDFs, cookies, tokens, URLs, hidden fields, and audit metadata
- what is stored, transmitted, cached, logged, displayed, or discarded

Use the minimum necessary data. Keep credentials, session material, raw clinical content, and derived summaries in separate trust domains.

### 3. Preserve privacy and security defaults

- Never commit patient data, real reports, credentials, tokens, cookies, API keys, screenshots, or production logs.
- Use synthetic or explicitly de-identified fixtures for tests and examples.
- Block external AI by default when PHI or unreviewed clinical data may be present.
- Require explicit policy, user action, de-identification preview, and audit logging before permitted external transmission.
- Protect exports against formula injection and accidental identifier inclusion.
- Use named users, least privilege, secure sessions, CSRF protection, rate limits, audit trails, backup verification, and restore testing where applicable.
- Do not automate login, captcha, OTP, or session circumvention unless an approved system interface explicitly supports it.

### 4. Preserve source fidelity and provenance

Every derived value or summary should retain enough provenance to answer:

- which source record/report produced it
- when it was retrieved and parsed
- which parser/version/rule produced it
- whether the source was complete, supported, and successfully validated
- what was omitted, ambiguous, or failed

Never silently convert a failed fetch, login page, viewer shell, image-only document, unsupported format, or partial response into clinical data.

### 5. Separate deterministic extraction from interpretation

- Prefer deterministic parsing for laboratory values, dates, organisms, susceptibilities, and report metadata.
- Validate units, reference ranges, decimal formats, dates, duplicate rows, amendments, and report versions.
- Keep summarization or clinical interpretation downstream of source extraction.
- Label AI-generated or heuristic output clearly and require clinician review.
- Never fabricate absent values or infer negative results from missing text.

### 6. Design failure safely

Use explicit states such as:

- source unavailable
- authentication/session expired
- unsupported format
- parse incomplete
- ambiguous value
- validation failed
- external AI blocked
- clinician review required

Fail closed for privacy, authorization, and destructive actions. Fail visibly for clinical-data incompleteness. Avoid broad exception suppression and silent fallbacks.

### 7. Validate against realistic hazards

Test at minimum:

- synthetic/de-identified normal and abnormal reports
- malformed, duplicated, amended, incomplete, and unsupported reports
- login/session-expired HTML and wrong endpoints
- image-only PDFs when OCR is unavailable
- identifier leakage through logs, exports, URLs, cache keys, diagnostics, and exceptions
- role/permission boundaries and audit events
- offline/reconnect/conflict behavior
- backup and restore integrity
- external-AI policy gates
- source-to-summary traceability
- human verification workflow

Use a documented validation matrix mapping hazards to tests and residual risk.

### 8. Release and change control

Before merge or deployment:

- review the diff for new data flows and trust boundaries
- update threat model, intended-use statement, and validation evidence when behavior changes
- run focused safety tests and the complete required suite on the final head
- verify no real clinical data or secrets entered the repository or artifacts
- document unresolved risks and rollback/recovery steps

## Validation

Completion requires evidence that privacy boundaries, deterministic extraction, failure classification, authorization, auditability, and source verification were tested. A successful happy-path demo alone is insufficient.

## Failure and uncertainty handling

When regulatory, institutional, ethical, or data-governance approval is unknown, state that the tool remains limited to supervised development or pilot use. Do not infer approval from technical capability. Escalate unresolved privacy, authorization, or patient-safety risks rather than accepting them as implementation details.

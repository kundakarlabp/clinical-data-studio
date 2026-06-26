---
name: robust-repo-change
description: Diagnose and implement repository changes through root-cause analysis, narrow diffs, architecture-preserving edits, regression tests, pull requests, review resolution, CI validation, and controlled merge.
---

# Robust Repository Change

## Purpose

Prevent repeated code churn, path drift, duplicate architecture, and unverified merges. Use repository evidence rather than speculative edits.

## Workflow

### 1. Establish repository truth

- Read all applicable `AGENTS.md` files.
- Inspect the authoritative runtime path, schema, migrations, tests, recent commits, open PRs, and CI configuration.
- Identify the owning module and interfaces that must remain stable.
- State the intended scope, data touched, and files that should not change.

### 2. Reproduce or define the failure

- Capture the exact symptom, expected behavior, environment, inputs, and failure evidence.
- Prefer a deterministic failing test, synthetic/de-identified fixture, minimal harness, or focused command.
- For intermittent failures, instrument one boundary at a time and collect evidence before editing.

### 3. Establish root cause

- Trace bad state or data to its source.
- Compare with a working path in the same repository.
- Form a falsifiable hypothesis and test the smallest variable.
- Do not patch symptoms, suppress broad exceptions, or add hidden fallbacks.

### 4. Implement narrowly

- Create a branch from current `main`.
- Add or update a regression test first when a valid seam exists.
- Make the smallest change in the owning module.
- Preserve public interfaces, schema compatibility, audit behavior, authorization, privacy boundaries, configuration semantics, and state ownership unless the task explicitly requires migration.
- Keep refactoring, feature work, and bug fixes separate.

### 5. Review the diff

Check for:

- unrelated formatting or renames
- duplicate persistence, authorization, audit, export, backup, or AI paths
- stale-data, race, idempotency, retry, conflict, and restart failures
- secrets, credentials, identifiers, raw clinical data, or unsafe fixtures
- unsafe defaults or silent fallbacks
- test mocks that bypass production behavior
- missing observability, provenance, rollback, restore, and recovery behavior

### 6. Validate

Run the exact repository-required commands plus focused tests for the changed path. Fresh evidence must include:

- compilation/build success
- focused regression, privacy, and migration tests
- SQLite and PostgreSQL behavior when persistence changes
- complete required test suite
- CI result on the final PR head

For a regression test, verify that it would fail without the fix when practical.

### 7. PR and merge

- Open one focused PR with root cause, fix, affected paths, clinical-data/security impact, validation commands, and residual risk.
- Inspect automated review suggestions technically; do not accept them blindly.
- Resolve all valid review threads.
- Re-run CI after the final change.
- Merge only when the final head is mergeable and all required checks pass.
- Report the PR and merge commit accurately.

## Validation

Completion requires fresh command output or CI evidence for the final branch head. A previous run, partial suite, plausible diff, or agent statement is not sufficient evidence.

## Clinical-data and production safeguards

- Never weaken privacy, authorization, auditability, external-AI gates, record locks/freezes, export safety, backup verification, or restore behavior to make tests pass.
- Never use real participant data, identifiers, credentials, database files, backups, or production logs in tests.
- Preserve named-user access, least privilege, CSRF protection, data-access groups, and token revocation.
- Preserve deterministic migrations and explicit rollback/recovery behavior across SQLite and PostgreSQL.
- Do not claim regulatory compliance or production validation without documented evidence.

## Failure and uncertainty handling

If the issue cannot be reproduced or required tests cannot run, do not claim completion. Report the evidence collected, the exact blocker, the remaining clinical-data/security risk, and the next diagnostic action.

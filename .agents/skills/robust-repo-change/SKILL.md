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
- Inspect the authoritative runtime path, architecture documents, tests, recent commits, open PRs, and CI configuration.
- Identify the owning module and interfaces that must remain stable.
- State the intended scope and files that should not change.

### 2. Reproduce or define the failure

- Capture the exact symptom, expected behavior, environment, inputs, and failure evidence.
- Prefer a deterministic failing test, replay fixture, minimal harness, or focused command.
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
- Preserve public interfaces, configuration semantics, risk controls, and state ownership unless the task explicitly requires migration.
- Keep refactoring, feature work, and bug fixes separate.

### 5. Review the diff

Check for:

- unrelated formatting or renames
- duplicate runtime paths or owners
- stale-data, race, idempotency, retry, and restart failures
- secrets or credentials
- unsafe defaults
- test mocks that bypass production behavior
- backtest/live divergence for trading systems
- missing observability and recovery behavior

### 6. Validate

Run the exact repository-required commands plus focused tests for the changed path. Fresh evidence must include:

- compilation/build success
- lint/type checks when configured
- focused regression tests
- complete required test suite
- CI result on the final PR head

For a regression test, verify that it would fail without the fix when practical.

### 7. PR and merge

- Open one focused PR with root cause, fix, affected paths, safety impact, validation commands, and residual risk.
- Inspect automated review suggestions technically; do not accept them blindly.
- Resolve all valid review threads.
- Re-run CI after the final change.
- Merge only when the final head is mergeable and all required checks pass.
- Report the PR and merge commit accurately.

## Validation

Completion requires fresh command output or CI evidence for the final branch head. A previous run, partial suite, plausible diff, or agent statement is not sufficient evidence.

## Trading and production safeguards

- Never weaken readiness, risk, capital, position, cooldown, max-loss, execution-mode, or secret-management controls to make tests pass.
- Never place live orders during testing.
- Preserve paper/shadow/live separation.
- Treat broker acknowledgement, partial fills, retries, reconnects, and restart recovery as explicit state transitions.

## Failure and uncertainty handling

If the issue cannot be reproduced or required tests cannot run, do not claim completion. Report the evidence collected, the exact blocker, the remaining risk, and the next diagnostic action.

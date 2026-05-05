# Clinical Data Studio

A local-network electronic data capture app for small clinical research projects.

## What it does now

- Runs on one laptop/desktop and serves phones/tablets on the same Wi-Fi.
- Stores data in local SQLite.
- Provides study setup, CRF schema editing, participant registry, data entry, review queries, audit trail, CSV export, and simple analysis.
- Supports server-side edit checks, repeatable CRFs, lock/unlock review flow, data quality review, and codebook export.
- Uses no paid cloud server and no subscription.

## Start

```powershell
python .\server.py
```

Open the shown URL on this computer. To use from a phone, connect the phone to the same Wi-Fi and open:

```text
http://<this-computer-ip>:8765
```

Default login:

```text
admin / admin123
```

Change this before real research use.

## Scope

This is an early local-first EDC foundation. It is not yet validated for FDA 21 CFR Part 11, HIPAA, GCP, or sponsor-regulated pivotal trials. Those require validation records, SOPs, access controls, backup procedures, and documented audit review in addition to software features.

## REDCap-like Feature Roadmap

Implemented foundation:

- Metadata-driven instruments and fields
- Required/range/choice edit checks
- Branching logic for simple show-if rules
- Repeat instances for repeatable CRFs
- Participant registry and event-based CRF entry
- Data queries and data quality dashboard
- Audit trail for create/update/lock/unlock actions
- CSV data export and codebook export
- Data dictionary CSV import
- Version history for edited CRFs
- Calculated fields
- Field-level verification/freeze
- Query response history
- Saved reports and filtered report export
- Local backup, download, and restore
- Optional passphrase-protected encrypted archive export
- Health endpoint and local LAN start helper
- Local CRF draft assistant from pasted text
- Local analysis/review assistant summary
- API and mobile shell regression tests

Next planned build steps:

- Desktop shortcut/installer packaging
- Optional audited database-at-rest encryption layer
- Broader browser automation across common Android/iOS viewport sizes

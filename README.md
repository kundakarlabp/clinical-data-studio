# Clinical Data Studio

A local-network electronic data capture app for small clinical research projects.

## What it does now

- Runs on one laptop/desktop and serves phones/tablets on the same Wi-Fi.
- Stores data in local SQLite.
- Provides study setup, CRF schema editing, participant registry, data entry, review queries, audit trail, CSV export, and simple analysis.
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

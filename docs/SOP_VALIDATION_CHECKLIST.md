# Clinical Data Studio SOP And Validation Checklist

## Before Real Study Use

- Change the default `admin / admin123` password.
- Create named users for each data collector and reviewer.
- Assign project roles and data access groups.
- Create a local backup and copy it to encrypted external storage.
- Confirm phone access only on the intended trusted Wi-Fi network.

## Build Validation

- Run `python -m py_compile .\server.py`.
- Run `node --check .\static\app.js`.
- Start with `.\start.ps1`.
- Confirm login, participant creation, CRF save, query creation, query response, field verify/freeze, export, codebook export, report export, backup, and restore.

## Study Operation

- Review open queries before analysis export.
- Lock CRFs only after source review.
- Record reasons for locked-data changes.
- Keep dated backup copies after each data-entry session.
- Export de-identified datasets for analysis whenever possible.

## Compliance Note

This checklist supports internal validation discipline. It does not by itself make the app FDA 21 CFR Part 11, HIPAA, or GCP validated.

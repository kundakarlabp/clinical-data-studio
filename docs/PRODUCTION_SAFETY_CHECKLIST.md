# Production Safety Checklist

Complete this before real study data entry.

## Required

- Named user account for every person.
- No shared admin account for study work.
- HTTPS enabled.
- Strong admin password stored outside GitHub.
- `.env` is not committed.
- `data/`, backups, logs, uploads, and exports are not committed.
- Backups enabled.
- Full backup includes PostgreSQL database and uploaded evidence files.
- Latest full backup verification passed.
- Restore tested at least once.
- Audit trail reviewed.
- AI audit page reviewed if AI helpers were used.
- Data Entry users cannot export.
- Analyst users cannot edit records.
- Users cannot see unassigned projects.
- External AI is disabled for PHI unless approved.
- De-identified exports preferred for analysis.

## Commands

Check health:

```bash
docker compose exec app python server.py healthcheck
```

Create PostgreSQL-only backup:

```bash
bash scripts/backup_postgres.sh
```

Create and verify full backup:

```bash
bash scripts/backup_full.sh
bash scripts/verify_backup.sh full_YYYYMMDD_HHMMSS.full.cdsenc
```

View logs:

```bash
bash scripts/logs.sh
```

Run migrations:

```bash
docker compose exec app python server.py migrate
```

## Sign-Off

Record:

- Date
- Study name
- Person checking
- Backup file name
- Full backup verification result
- Restore drill result
- HTTPS URL
- Admin account reviewed
- User roles reviewed

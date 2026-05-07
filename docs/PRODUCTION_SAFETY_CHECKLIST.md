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
- Restore tested at least once.
- Audit trail reviewed.
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

Create backup:

```bash
bash scripts/backup_postgres.sh
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
- Restore drill result
- HTTPS URL
- Admin account reviewed
- User roles reviewed

# Backup And Restore

Backups protect the study database. Keep the backup passphrase outside the server and outside GitHub.

## Create A PostgreSQL Backup

```bash
cd clinical-data-studio
bash scripts/backup_postgres.sh
```

If `CDS_BACKUP_PASSPHRASE` is set in `.env`, the script creates an encrypted backup.

## List Backups

```bash
ls -lh backups
```

## Restore A PostgreSQL Backup

Use only after confirming you are restoring the correct file.

```bash
cd clinical-data-studio
bash scripts/restore_postgres.sh backups/postgres_YYYYMMDD_HHMMSS.dump.gz
```

For encrypted backups:

```bash
bash scripts/restore_postgres.sh backups/postgres_YYYYMMDD_HHMMSS.dump.gz.enc
```

The script asks you to type `RESTORE`.

## App-Level Backup Command

Inside Docker:

```bash
docker compose exec app python server.py backup
```

Restore:

```bash
docker compose exec app python server.py restore system_YYYYMMDD_HHMMSS.dump
```

## Restore Drill

Do a restore drill before real study use:

1. Create a test project.
2. Add one participant and one CRF entry.
3. Create a backup.
4. Restore the backup on a test server or test container.
5. Confirm login, participant, CRF, and audit log.
6. Record the result in the safety checklist.

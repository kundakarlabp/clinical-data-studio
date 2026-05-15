# Backup And Restore

Backups protect the study database and uploaded evidence. Keep the backup passphrase outside the server and outside GitHub. If you lose the passphrase, encrypted backups cannot be opened.

## Backup Types

Lightsail snapshot:

- AWS-level snapshot of the whole server disk.
- Useful if the server is damaged or deleted.
- Not a replacement for app-level backups because restore testing is less granular.

PostgreSQL backup:

- Database dump only.
- Contains users, studies, CRFs, participants, entries, audit log, case metadata, and academic workbench data.
- Does not contain uploaded photos, PDFs, audio, or other Case Intake evidence files.

Full app backup:

- Encrypted Clinical Data Studio archive.
- Contains PostgreSQL dump plus uploaded evidence files.
- Includes `manifest.json` and `SHA256SUMS.txt` for verification.
- This is the preferred routine backup for non-coder admins.

Clinical Data Studio stores large Case Intake evidence files in `uploads/`, not inside the database. A safe backup plan must protect both:

- PostgreSQL database: participants, CRFs, entries, audit, case metadata, AI reviews.
- Upload folder: case photos, PDFs, audio, and text evidence.

## Recommended Browser Method

Use **Admin -> Backups**:

1. Click **Create Full Backup**.
2. Click **Verify Latest Backup**.
3. Confirm the page says the latest full backup is verified.
4. Click **Download Full Backup** if you want an external encrypted copy.

Do this instead of terminal commands for routine use.

## Create A Full Backup From Terminal

Use this only if you are comfortable with the server terminal:

```bash
cd clinical-data-studio
bash scripts/backup_full.sh
bash scripts/verify_backup.sh full_YYYYMMDD_HHMMSS.full.cdsenc
```

Dry-run restore check:

```bash
bash scripts/restore_full_dry_run.sh full_YYYYMMDD_HHMMSS.full.cdsenc
```

The dry run decrypts, lists, and verifies checksums. It does not overwrite the production database or uploads.

## Create A PostgreSQL Backup

```bash
cd clinical-data-studio
bash scripts/backup_postgres.sh
```

If `CDS_BACKUP_PASSPHRASE` is set in `.env`, the script creates an encrypted backup.

The Docker Compose deployment keeps upload files in the `cds_uploads` volume. For a full server backup, also copy or snapshot that volume. On a small Lightsail server, the simplest safe route is:

```bash
docker run --rm -v clinical-data-studio_cds_uploads:/uploads -v "$PWD/backups:/backups" alpine tar -czf /backups/uploads_$(date +%Y%m%d_%H%M%S).tar.gz -C /uploads .
```

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
4. Upload one test PDF/photo in Case Intake.
5. Back up the upload volume.
6. Restore database and uploads on a test server or test container.
7. Confirm login, participant, CRF, audit log, and file download.
8. Record the result in the safety checklist.

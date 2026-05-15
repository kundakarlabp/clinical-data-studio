# AWS Lightsail Non-Coder Deployment

This guide deploys Clinical Data Studio on a low-cost AWS Lightsail Ubuntu server with Docker Compose, PostgreSQL, and Nginx.

## 1. Create The Lightsail Server

1. Open AWS Lightsail.
2. Create an Ubuntu instance in Mumbai, `ap-south-1`.
3. Choose the smallest plan that has enough disk for your study files.
4. Attach a static IP.
5. Point your domain DNS `A` record to that static IP.

## 2. Install Docker

SSH into the server, then run:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker
docker --version
docker compose version
```

## 3. Clone The App

```bash
git clone https://github.com/kundakarlabp/clinical-data-studio.git
cd clinical-data-studio
```

## 4. Configure Secrets

```bash
cp .env.example .env
nano .env
```

Change every `CHANGE_ME` value. Use long passwords. Keep `CDS_AI_ENABLED=false` unless you have written approval to send de-identified data to external AI.

Generate a long secret:

```bash
openssl rand -hex 32
```

Keep these storage settings:

```text
CDS_DATABASE_BACKEND=postgres
CDS_UPLOAD_DIR=/app/uploads
CDS_BACKUP_DIR=/app/backups
CDS_AI_ENABLED=false
CDS_AI_ALLOW_PHI=false
```

Do not use SQLite for real production data on Lightsail.

## 5. Start The App

```bash
docker compose build
docker compose up -d
docker compose logs --tail=100 app
```

Check health:

```bash
docker compose exec app python server.py healthcheck
```

Open:

```text
http://YOUR_STATIC_IP
```

## 6. Enable HTTPS

Install the first certificate after your domain points to the server:

```bash
docker compose run --rm certbot certonly --webroot --webroot-path /var/www/certbot -d your-domain.example
```

Then replace `deploy/nginx/clinical-data-studio.conf` with the contents of `deploy/nginx/clinical-data-studio-https.conf.example`, replace `your-domain.example`, and restart:

```bash
docker compose restart nginx
```

Set this in `.env`:

```text
CDS_REQUIRE_HTTPS=true
CDS_PUBLIC_BASE_URL=https://your-domain.example
```

Restart:

```bash
docker compose up -d
```

## 7. Create First Admin

The startup script creates or updates the admin from `.env`.

To run it manually:

```bash
docker compose exec app python server.py create-admin
```

## 8. Verify Study Workflow

1. Log in.
2. Create a project.
3. Create forms.
4. Add users.
5. Assign project roles.
6. Open the site from mobile.
7. Create one test participant.
8. Enter one test CRF.
9. Check Audit Trail.
10. Create a backup.
11. Upload one test PDF or photo in Case Intake.
12. Confirm the file appears in the app and downloads.

## 9. Update Later

```bash
bash scripts/update.sh
```

## 10. Routine Admin Schedule

Daily after data entry:

1. Open **Admin -> Backups**.
2. Click **Create Full Backup**.
3. Click **Verify Latest Backup**.
4. Confirm the latest full backup says verified.
5. Review **Audit Trail** for unexpected exports, failed logins, backup downloads, or AI calls.

Weekly:

1. Download one encrypted full backup to a safe external location.
2. Keep the passphrase separately.
3. Check that Lightsail automatic snapshots are still enabled.

Monthly:

1. Do a restore drill on a test server or temporary copy.
2. Confirm login, participants, CRFs, entries, audit, and uploaded files.
3. Record the result in the study validation checklist.

View logs:

```bash
bash scripts/logs.sh
```

Restart:

```bash
docker compose restart app
```

Update:

```bash
bash scripts/update.sh
```

Create users:

1. Log in as System Admin.
2. Open **Access**.
3. Create a named user.
4. Assign that user to the project.
5. Choose Data Entry, Reviewer, Analyst, Viewer, or Project Admin / PI.
6. Assign a data access group if the user should see only one site/group.

## 11. Android Use

On Android Chrome:

1. Open `https://your-domain.example`.
2. Log in with the named account created by the admin.
3. Tap **Install App** if shown.
4. If not shown, open Chrome menu and tap **Add to Home screen**.
5. Use **Data Entry** for CRFs and **Case Intake** for photos, PDFs, audio, and rough notes.
6. Open **Local Drafts** before leaving the clinic if the phone was offline.

## 12. What Not To Do

- Do not upload live patient data to GitHub.
- Do not email the `.env` file.
- Do not share the admin account.
- Do not delete the `postgres_data`, `cds_uploads`, or `cds_backups` Docker volumes.
- Do not enable external AI for PHI unless your ethics and institutional policy explicitly allow it.
- Do not rely on PostgreSQL-only backup if your study uses uploaded evidence files.

## 13. Official References

- AWS Lightsail docs: https://docs.aws.amazon.com/lightsail/
- Docker Engine install docs: https://docs.docker.com/engine/install/ubuntu/
- Docker Compose docs: https://docs.docker.com/compose/
- Certbot docs: https://certbot.eff.org/

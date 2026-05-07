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

## 9. Update Later

```bash
bash scripts/update.sh
```

## 10. Official References

- AWS Lightsail docs: https://docs.aws.amazon.com/lightsail/
- Docker Engine install docs: https://docs.docker.com/engine/install/ubuntu/
- Docker Compose docs: https://docs.docker.com/compose/
- Certbot docs: https://certbot.eff.org/

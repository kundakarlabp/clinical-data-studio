# Troubleshooting

## App Does Not Open

Check containers:

```bash
docker compose ps
```

Check logs:

```bash
bash scripts/logs.sh
```

Check health:

```bash
docker compose exec app python server.py healthcheck
```

## Production Startup Refused

The app refuses unsafe production startup if:

- `CDS_SECRET_KEY` is missing or weak.
- `CDS_ADMIN_PASSWORD` is missing, weak, or `admin123`.
- `CDS_REQUIRE_HTTPS=true` but `CDS_PUBLIC_BASE_URL` is not HTTPS.

Edit `.env`, then restart:

```bash
nano .env
docker compose up -d
```

## Cannot Log In

If repeated failed logins locked the account, wait 15 minutes or reset the password as super admin.

```bash
docker compose exec -e CDS_FORCE_ADMIN_RESET=true app python server.py create-admin
```

## Database Not Ready

Check PostgreSQL:

```bash
docker compose logs --tail=100 db
docker compose exec db pg_isready -U clinical -d clinical_data_studio
```

Run migrations:

```bash
docker compose exec app python server.py migrate
```

## HTTPS Certificate Problem

Confirm DNS points to the Lightsail static IP:

```bash
dig your-domain.example
```

Run Certbot again:

```bash
docker compose run --rm certbot certonly --webroot --webroot-path /var/www/certbot -d your-domain.example
```

Restart Nginx:

```bash
docker compose restart nginx
```

## Backup Failed

Check disk:

```bash
df -h
```

Check backup folder:

```bash
ls -lh backups
```

Run:

```bash
bash scripts/backup_postgres.sh
```

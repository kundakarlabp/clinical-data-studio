#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "Before updating, confirm Admin -> Backups shows a verified full backup from the last 7 days."
echo "A full backup must include both the PostgreSQL database and uploaded evidence files."
echo "Lightsail snapshots alone are not enough for routine study backup."

git pull --ff-only
docker compose build app
docker compose up -d
docker compose exec -T app python server.py migrate
docker compose exec -T app python server.py healthcheck

#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# shellcheck disable=SC1091
source scripts/env.sh
load_cds_env .env

if [[ -z "${CDS_BACKUP_PASSPHRASE:-}" ]]; then
  echo "Set CDS_BACKUP_PASSPHRASE in .env before creating a full encrypted backup."
  exit 1
fi

echo "Creating encrypted full backup inside the app backup directory..."
docker compose exec -T app python server.py backup-full
echo "Full backup complete. Download it from Admin -> Backups if you need an external copy."


#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# shellcheck disable=SC1091
source scripts/env.sh
load_cds_env .env

backup_file="${1:-}"
if [[ -z "$backup_file" ]]; then
  echo "Usage: scripts/verify_backup.sh full_YYYYMMDD_HHMMSS.full.cdsenc"
  exit 1
fi

if [[ -z "${CDS_BACKUP_PASSPHRASE:-}" ]]; then
  echo "Set CDS_BACKUP_PASSPHRASE in .env before verifying an encrypted backup."
  exit 1
fi

echo "Verifying encrypted full backup without restoring production data..."
docker compose exec -T app python server.py verify-backup "$backup_file"
echo "Full backup verification finished."


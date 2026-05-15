#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# shellcheck disable=SC1091
source scripts/env.sh
load_cds_env .env

backup_file="${1:-}"
if [[ -z "$backup_file" ]]; then
  echo "Usage: scripts/restore_full_dry_run.sh full_YYYYMMDD_HHMMSS.full.cdsenc"
  exit 1
fi

if [[ -z "${CDS_BACKUP_PASSPHRASE:-}" ]]; then
  echo "Set CDS_BACKUP_PASSPHRASE in .env before testing an encrypted backup."
  exit 1
fi

echo "Dry-run only: decrypt/list/checksums. Production database and uploads will not be changed."
docker compose exec -T app python server.py restore-full-dry-run "$backup_file"
echo "Dry-run restore verification passed."


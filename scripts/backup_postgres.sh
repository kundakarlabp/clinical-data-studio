#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

mkdir -p backups
timestamp="$(date +%Y%m%d_%H%M%S)"
plain="backups/postgres_${timestamp}.dump.gz"
encrypted="${plain}.enc"

docker compose exec -T db pg_dump -U clinical -d clinical_data_studio --format=custom | gzip > "$plain"

if [[ -n "${CDS_BACKUP_PASSPHRASE:-}" ]]; then
  openssl enc -aes-256-cbc -salt -pbkdf2 -in "$plain" -out "$encrypted" -pass "pass:${CDS_BACKUP_PASSPHRASE}"
  rm -f "$plain"
  echo "Encrypted backup created: $encrypted"
else
  echo "Backup created: $plain"
fi

find backups -name 'postgres_*.dump.gz*' -type f -mtime +90 -delete

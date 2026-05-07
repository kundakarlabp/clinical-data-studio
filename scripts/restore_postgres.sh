#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

backup_file="${1:-}"
if [[ -z "$backup_file" || ! -f "$backup_file" ]]; then
  echo "Usage: scripts/restore_postgres.sh backups/postgres_YYYYMMDD_HHMMSS.dump.gz[.enc]"
  exit 1
fi

echo "This will replace the PostgreSQL data in the running Clinical Data Studio database."
read -r -p "Type RESTORE to continue: " confirm
if [[ "$confirm" != "RESTORE" ]]; then
  echo "Restore cancelled."
  exit 1
fi

tmp="$(mktemp)"
cleanup() {
  rm -f "$tmp"
}
trap cleanup EXIT

if [[ "$backup_file" == *.enc ]]; then
  if [[ -z "${CDS_BACKUP_PASSPHRASE:-}" ]]; then
    echo "Set CDS_BACKUP_PASSPHRASE before decrypting this backup."
    exit 1
  fi
  openssl enc -d -aes-256-cbc -pbkdf2 -in "$backup_file" -out "$tmp.gz" -pass "pass:${CDS_BACKUP_PASSPHRASE}"
  gunzip -c "$tmp.gz" > "$tmp"
  rm -f "$tmp.gz"
else
  gunzip -c "$backup_file" > "$tmp"
fi

docker compose exec -T db pg_restore -U clinical -d clinical_data_studio --clean --if-exists --no-owner < "$tmp"
docker compose exec -T app python server.py migrate
docker compose exec -T app python server.py healthcheck

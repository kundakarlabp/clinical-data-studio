#!/usr/bin/env bash
set -euo pipefail

mkdir -p "${CDS_DATA_DIR:-/app/data}" "${CDS_BACKUP_DIR:-/app/backups}" "${CDS_LOG_DIR:-/app/logs}" /app/uploads

python server.py migrate
python server.py create-admin

exec python server.py

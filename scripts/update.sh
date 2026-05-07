#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

git pull --ff-only
docker compose build app
docker compose up -d
docker compose exec -T app python server.py migrate
docker compose exec -T app python server.py healthcheck

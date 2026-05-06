#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo: sudo bash deploy/install_linux_service.sh"
  exit 1
fi

APP_DIR="${APP_DIR:-$(pwd)}"
APP_USER="${APP_USER:-cds}"
APP_PORT="${CDS_PORT:-8765}"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
SERVICE_FILE="/etc/systemd/system/clinical-data-studio.service"

if [ ! -f "$APP_DIR/server.py" ]; then
  echo "server.py was not found in $APP_DIR"
  echo "Run this from the cloned clinical-data-studio repository, or set APP_DIR."
  exit 1
fi

if [ ! -x "$PYTHON_BIN" ]; then
  echo "$PYTHON_BIN was not found. Install python3 first."
  exit 1
fi

if ! getent group "$APP_USER" >/dev/null 2>&1; then
  groupadd --system "$APP_USER"
fi

if ! id -u "$APP_USER" >/dev/null 2>&1; then
  useradd --system --gid "$APP_USER" --home "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"
fi

install -d -o "$APP_USER" -g "$APP_USER" "$APP_DIR/data" "$APP_DIR/data/backups"
chown -R "$APP_USER:$APP_USER" "$APP_DIR/data"

cat > "$SERVICE_FILE" <<SERVICE
[Unit]
Description=Clinical Data Studio
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
Environment=CDS_PORT=$APP_PORT
ExecStart=$PYTHON_BIN $APP_DIR/server.py
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=$APP_DIR/data

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now clinical-data-studio.service
systemctl --no-pager status clinical-data-studio.service

echo ""
echo "Clinical Data Studio service installed."
echo "Local URL on this VM: http://127.0.0.1:$APP_PORT"
echo "Prefer Tailscale or Cloudflare Tunnel before exposing this service publicly."

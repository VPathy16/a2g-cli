#!/usr/bin/env bash
# A2G on-target installer for Raspberry Pi (P6).
#
# Run this script on the Pi AFTER extracting the tarball:
#
#   tar -xzf a2g-rpi-v0.2.0-aarch64.tar.gz
#   sudo bash install.sh
#
# What this does:
#   1. Copies binaries to /usr/local/bin
#   2. Installs a systemd service for a2g-gateway (auto-start, --state-ingest)
#   3. Sets up the vcan0 virtual CAN interface via a systemd-networkd link file
#      (requires vcan kernel module; instructions printed if absent)
#   4. Enables and starts a2g-gateway.service

set -euo pipefail

INSTALL_DIR="/usr/local/bin"
SERVICE_DIR="/etc/systemd/system"
KEYS_PATH="/etc/a2g/demo-keys.json"
QUEUE_PATH="/var/lib/a2g/pending-queue.json"

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: this installer must be run as root (sudo bash install.sh)"
  exit 1
fi

echo "[install] Copying binaries to ${INSTALL_DIR}…"
install -m 0755 bin/a2g-gateway   "${INSTALL_DIR}/a2g-gateway"
install -m 0755 bin/a2g-state-sim "${INSTALL_DIR}/a2g-state-sim"
install -m 0755 bin/a2g           "${INSTALL_DIR}/a2g"

# ── Create required directories ────────────────────────────────────────────────
mkdir -p "$(dirname "${KEYS_PATH}")"
mkdir -p "$(dirname "${QUEUE_PATH}")"

# ── vcan0 setup ───────────────────────────────────────────────────────────────
echo "[install] Checking vcan kernel module…"
if modprobe vcan 2>/dev/null; then
  ip link add dev vcan0 type vcan 2>/dev/null || true
  ip link set up vcan0 2>/dev/null || true
  echo "[install] vcan0 is up."
else
  echo "[install] WARNING: vcan module not found."
  echo "[install]   On Raspberry Pi OS: sudo apt-get install raspberrypi-kernel-headers"
  echo "[install]   Then reboot and re-run this installer."
fi

# ── systemd service for a2g-gateway ───────────────────────────────────────────
cat > "${SERVICE_DIR}/a2g-gateway.service" <<'SERVICE'
[Unit]
Description=A2G Enforcing Gateway
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/a2g-gateway \
    --socket /tmp/a2g-gateway.sock \
    --vcan vcan0 \
    --keys /etc/a2g/demo-keys.json \
    --state-ingest \
    --queue-persist /var/lib/a2g/pending-queue.json
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
SERVICE

# ── systemd service for a2g-state-sim (optional demo simulator) ───────────────
cat > "${SERVICE_DIR}/a2g-state-sim.service" <<'SERVICE'
[Unit]
Description=A2G State Simulator (vcan0, parked at 0 km/h)
After=a2g-gateway.service

[Service]
Type=simple
ExecStart=/usr/local/bin/a2g-state-sim \
    --vcan vcan0 \
    --speed-kph 0.0 \
    --gear park
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
SERVICE

echo "[install] Enabling and starting a2g-gateway.service…"
systemctl daemon-reload
systemctl enable a2g-gateway.service
systemctl start  a2g-gateway.service

echo "[install] Done.  Check status with: systemctl status a2g-gateway"
echo "[install] Gateway keys: ${KEYS_PATH}"
echo "[install] Pending queue: ${QUEUE_PATH}"
echo ""
echo "To also start the state simulator:"
echo "  sudo systemctl enable --now a2g-state-sim.service"

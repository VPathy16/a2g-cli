A2G Enforcing Gateway — Raspberry Pi Demo Package v0.2.0
=========================================================

This tarball contains pre-built aarch64 binaries and an installer for
Raspberry Pi 4/5 running Raspberry Pi OS (64-bit, Debian-based).

Contents
--------
  bin/a2g-gateway    — Enforcing Gateway (Unix socket, SocketCAN)
  bin/a2g-state-sim  — State simulator (50 Hz E2E frames on vcan0)
  bin/a2g            — A2G CLI (governance decision tool)
  install.sh         — On-target installer (installs + enables systemd services)
  README.txt         — This file

Quick start
-----------
1. On the Pi:

    tar -xzf a2g-rpi-v0.2.0-aarch64.tar.gz
    sudo bash install.sh

2. Verify the gateway is running:

    systemctl status a2g-gateway
    cat /etc/a2g/demo-keys.json   # demo public keys

3. Start the state simulator (broadcasts Park / 0 km/h at 50 Hz):

    sudo systemctl enable --now a2g-state-sim

4. Run the demo CLI:

    a2g demo        # four-beat governance demo

Requirements
------------
  - Raspberry Pi OS (64-bit) Bookworm or later
  - Linux kernel ≥ 4.9 with vcan module
  - sudo / root access for install

  To load the vcan module manually (if not auto-loaded):
    sudo modprobe vcan
    sudo ip link add dev vcan0 type vcan
    sudo ip link set up vcan0

  Optionally install can-utils for a live CAN frame view:
    sudo apt-get install can-utils
    candump vcan0

Architecture
------------
  ┌─────────────┐ Unix socket (CBOR)  ┌─────────────────┐
  │  a2g CLI /  │ ─────────────────── │  a2g-gateway    │
  │  rich domain│ ◄── ENFORCED ──────  │  (this Pi)      │
  └─────────────┘                      └────────┬────────┘
                                                │ SocketCAN
                                        ┌───────┴───────┐
                                        │  vcan0 / CAN  │
                                        │  a2g-state-sim│
                                        └───────────────┘

  The gateway subscribes to vcan0, verifies AUTOSAR-E2E integrity on every
  speed and gear frame (CRC-8/SAE-J1850 + alive counter), and re-gates
  Sensitive enforcement against its own bus readings.

Logs
----
  journalctl -u a2g-gateway -f
  journalctl -u a2g-state-sim -f

Support
-------
  GitHub: https://github.com/vpathy16/a2g-cli

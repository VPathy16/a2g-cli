#!/usr/bin/env bash
# A2G governance demo — full setup + run
#
# Usage:
#   sudo ./scripts/demo.sh          # sets up vcan0, runs demo, cleans up
#   sudo ./scripts/demo.sh --pause  # same, but waits for Enter between beats
#
# Requirements: Linux, vcan kernel module, Rust toolchain.
# The script brings up vcan0, starts the bus listener in the background,
# runs the four-beat showcase, then tears down vcan0 on exit.

set -euo pipefail

IFACE="vcan0"
PAUSE_FLAG=""
BINARY="./target/release/a2g-demo"

for arg in "$@"; do
    case "$arg" in
        --pause) PAUSE_FLAG="--pause" ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

# ── Require root for ip link operations ──────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "error: this script must be run as root (needs 'ip link' for vcan setup)"
    echo "       sudo ./scripts/demo.sh $*"
    exit 1
fi

# ── Build ─────────────────────────────────────────────────────────────────────
echo "==> Building a2g-demo …"
cargo build --release -p a2g-demo 2>&1

# ── vcan setup ────────────────────────────────────────────────────────────────
echo "==> Loading vcan kernel module …"
modprobe vcan

echo "==> Bringing up $IFACE …"
if ip link show "$IFACE" &>/dev/null; then
    echo "    $IFACE already exists — reusing it"
else
    ip link add dev "$IFACE" type vcan
    ip link set up "$IFACE"
    echo "    $IFACE is up"
fi

# Tear down vcan0 on exit (only if we created it).
CREATED_IFACE=0
ip link show "$IFACE" &>/dev/null && CREATED_IFACE=1

cleanup() {
    echo ""
    echo "==> Stopping listener …"
    kill "$LISTENER_PID" 2>/dev/null || true
    if [[ $CREATED_IFACE -eq 1 ]]; then
        echo "==> Tearing down $IFACE …"
        ip link del "$IFACE" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ── Start bus listener ────────────────────────────────────────────────────────
echo ""
echo "==> Starting bus listener on $IFACE …"
echo "    (A2G enforcement frames — CAN ID 0x7A2 — will appear here)"
echo "──────────────────────────────────────────────────────────────"
"$BINARY" listen --iface "$IFACE" &
LISTENER_PID=$!
sleep 0.3   # give the listener socket a moment to bind

# ── Run showcase ──────────────────────────────────────────────────────────────
echo ""
echo "==> Running four-beat governance showcase …"
echo "    Silence on the listener during beats 2 and 3 is intentional."
echo "──────────────────────────────────────────────────────────────"
echo ""
# shellcheck disable=SC2086
"$BINARY" run --vcan "$IFACE" $PAUSE_FLAG

echo ""
echo "==> Demo complete."

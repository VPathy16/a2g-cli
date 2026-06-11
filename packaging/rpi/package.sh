#!/usr/bin/env bash
# Raspberry Pi demo packaging script (P6).
#
# Cross-compiles all A2G binaries for aarch64-unknown-linux-gnu and bundles
# them into a self-contained tarball ready to deploy to a Raspberry Pi 4/5.
#
# Prerequisites (on the build host):
#   rustup target add aarch64-unknown-linux-gnu
#   sudo apt-get install gcc-aarch64-linux-gnu
#
# Usage:
#   bash packaging/rpi/package.sh [--output <dir>]
#
# Output:
#   a2g-rpi-v0.2.0-aarch64.tar.gz  (default: ./dist/)
#
# The tarball contains:
#   bin/a2g-gateway
#   bin/a2g-state-sim
#   bin/a2g
#   install.sh          — on-target installer (creates systemd services)
#   README.txt

set -euo pipefail

VERSION="0.2.0"
TARGET="aarch64-unknown-linux-gnu"
LINKER="aarch64-linux-gnu-gcc"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/dist"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUTPUT_DIR="$2"; shift 2 ;;
    *) echo "unknown flag: $1"; exit 1 ;;
  esac
done

mkdir -p "${OUTPUT_DIR}"
ARCHIVE="a2g-rpi-v${VERSION}-aarch64.tar.gz"
STAGING="$(mktemp -d)"
trap 'rm -rf "${STAGING}"' EXIT

echo "[package] Cross-compiling for ${TARGET}…"
cd "${REPO_ROOT}"
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="${LINKER}" \
  cargo build --release \
  --target "${TARGET}" \
  -p a2g-gateway \
  -p a2g-cli

BINS_DIR="${STAGING}/bin"
mkdir -p "${BINS_DIR}"
cp "target/${TARGET}/release/a2g-gateway"   "${BINS_DIR}/"
cp "target/${TARGET}/release/a2g-state-sim" "${BINS_DIR}/"
cp "target/${TARGET}/release/a2g"           "${BINS_DIR}/"

# Copy the installer and README into the staging area.
cp "${SCRIPT_DIR}/install.sh"  "${STAGING}/"
cp "${SCRIPT_DIR}/README.txt"  "${STAGING}/"
chmod +x "${STAGING}/install.sh"

echo "[package] Building archive ${ARCHIVE}…"
tar -czf "${OUTPUT_DIR}/${ARCHIVE}" -C "${STAGING}" .

echo "[package] Done: ${OUTPUT_DIR}/${ARCHIVE}"

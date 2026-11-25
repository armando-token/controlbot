#!/usr/bin/env bash
# Deploy wrapper delegating Linux N3 verification to scripts/verify_n3_linux.sh
# Status: PENDING_N3_LINUX_ENV on non-Linux hosts (Darwin)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
exec "${REPO_ROOT}/scripts/verify_n3_linux.sh" "$@"

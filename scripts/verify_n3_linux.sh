#!/usr/bin/env bash
# Target Linux N3 Verification Script for Grokbot-clon
# Status: PENDING_N3_LINUX_ENV (authored on macOS; requires Linux host + netns/iptables/nft + local LLM)
set -euo pipefail

ALLOW_PENDING=0
if [[ "${1:-}" == "--allow-pending" ]]; then
  ALLOW_PENDING=1
fi

OS_NAME="$(uname -s)"
if [[ "$OS_NAME" != "Linux" ]]; then
  echo "[PENDING_N3_LINUX_ENV] Linux host required (detected $OS_NAME); N3 verification cannot run on this host." >&2
  if [[ "$ALLOW_PENDING" -eq 1 ]]; then
    exit 0
  fi
  exit 1
fi

echo "==> 1/5 Validating deploy/install_config.yaml"
uv run python -m deploy.config --config deploy/install_config.yaml --json >/dev/null

echo "==> 2/5 Inspecting Linux network namespace / firewall isolation"
if command -v ip >/dev/null 2>&1; then
  ip netns list || true
fi
if command -v nft >/dev/null 2>&1; then
  nft list ruleset >/dev/null 2>&1 || true
elif command -v iptables >/dev/null 2>&1; then
  iptables -S OUTPUT >/dev/null 2>&1 || true
fi

echo "==> 3/5 Verifying external internet egress is blocked (1.1.1.1:443 must fail)"
if uv run python -c "import socket, sys; s = socket.create_connection(('1.1.1.1', 443), timeout=2); s.close(); sys.exit(0)" 2>/dev/null; then
  echo "FAIL: External internet egress succeeded; outbound network block is not active!" >&2
  exit 2
fi
echo "PASS: External egress blocked."

echo "==> 4/5 Running strict N3 probe (Linux OS + A11 + AT-SPI + local LLM)"
uv run python -m src.n3_probe --strict --json

echo "==> 5/5 Running pytest N3 acceptance suite"
uv run pytest tests/acceptance -m n3 -rs -v

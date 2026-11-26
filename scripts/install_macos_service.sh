#!/usr/bin/env bash
# Install/manage ControlBot headless background server on macOS via launchd.
# Default mode is ultra-lean: loopback (127.0.0.1:8000) + --no-lab (zero idle Chromium/lab apps).

set -euo pipefail

LABEL="com.armandosilva.controlbot"
PLIST_PATH="${HOME}/Library/LaunchAgents/${LABEL}.plist"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UV_BIN="${UV_BIN:-$(command -v uv || echo "${HOME}/.local/bin/uv")}"
GUI_DOMAIN="gui/$(id -u)"

usage() {
  cat <<'EOF'
Usage: ./scripts/install_macos_service.sh <install|uninstall|status> [--lan] [--with-lab]
  install     Install and start headless launchd background server (default: 127.0.0.1:8000, --no-lab)
  --lan       Bind 0.0.0.0:8000 so another MacBook on local Wi-Fi can connect directly
  --with-lab  Also start synthetic lab portals (8101-8103); omitted by default to save RAM
  uninstall   Stop and remove launchd service
  status      Show launchd service status and /health check
EOF
}

cmd="${1:-}"
if [[ -z "$cmd" ]]; then
  usage
  exit 1
fi
shift || true

HOST="127.0.0.1"
WITH_LAB=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --lan)
      HOST="0.0.0.0"
      shift
      ;;
    --with-lab)
      WITH_LAB=1
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

case "$cmd" in
  install)
    if [[ ! -x "$UV_BIN" ]]; then
      echo "Error: uv executable not found at $UV_BIN" >&2
      exit 1
    fi
    mkdir -p "${HOME}/Library/LaunchAgents" "${REPO_DIR}/var"
    EXTRA_ARG=""
    if [[ "$WITH_LAB" -eq 0 ]]; then
      EXTRA_ARG="<string>--no-lab</string>"
    fi

    cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>WorkingDirectory</key>
  <string>${REPO_DIR}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${UV_BIN}</string>
    <string>run</string>
    <string>python</string>
    <string>-m</string>
    <string>src.local_server</string>
    <string>--host</string>
    <string>${HOST}</string>
    <string>--port</string>
    <string>8000</string>
    ${EXTRA_ARG}
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>${HOME}/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
    <key>PYTHONUNBUFFERED</key>
    <string>1</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${REPO_DIR}/var/launchd.out.log</string>
  <key>StandardErrorPath</key>
  <string>${REPO_DIR}/var/launchd.err.log</string>
</dict>
</plist>
EOF

    launchctl bootout "${GUI_DOMAIN}" "$PLIST_PATH" >/dev/null 2>&1 || true
    launchctl bootstrap "${GUI_DOMAIN}" "$PLIST_PATH"
    echo "Installed and started ${LABEL} (host=${HOST}, with_lab=${WITH_LAB})"
    echo "Plist: ${PLIST_PATH}"
    ;;

  uninstall)
    launchctl bootout "${GUI_DOMAIN}" "$PLIST_PATH" >/dev/null 2>&1 || true
    rm -f "$PLIST_PATH"
    echo "Uninstalled ${LABEL}"
    ;;

  status)
    if [[ -f "$PLIST_PATH" ]]; then
      echo "Plist installed: $PLIST_PATH"
    else
      echo "Plist not installed: $PLIST_PATH"
    fi
    launchctl print "${GUI_DOMAIN}/${LABEL}" 2>/dev/null | head -n 25 || echo "Service not loaded in ${GUI_DOMAIN}"
    curl -fsS http://127.0.0.1:8000/health 2>/dev/null || echo "Health endpoint not responding on 127.0.0.1:8000"
    ;;

  *)
    usage
    exit 1
    ;;
esac

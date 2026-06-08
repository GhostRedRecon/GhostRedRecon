#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[RunRedrecon] Delegating to scripts/start.sh so runtime URLs, ports, and GUI settings come from config/project.config.json"
exec bash "$ROOT_DIR/scripts/start.sh" "$@"

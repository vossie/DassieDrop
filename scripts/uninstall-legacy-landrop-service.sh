#!/usr/bin/env bash
set -euo pipefail

export SERVICE_NAME="${SERVICE_NAME:-landrop}"
export SERVICE_USER="${SERVICE_USER:-landrop}"
export SERVICE_GROUP="${SERVICE_GROUP:-landrop}"
export APP_DIR="${APP_DIR:-/opt/landrop}"
export DATA_DIR="${DATA_DIR:-/var/lib/landrop}"
export CONFIG_DIR="${CONFIG_DIR:-/etc/landrop}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${SCRIPT_DIR}/uninstall-ubuntu-service.sh" "$@"

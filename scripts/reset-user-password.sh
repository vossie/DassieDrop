#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <username> <password> <super-admin|admin|user>" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"

cd "${APP_DIR}"
PYTHONPATH="${APP_DIR}${PYTHONPATH:+:${PYTHONPATH}}" \
  "${PYTHON_BIN}" "${SCRIPT_DIR}/reset_admin_password.py" \
  --username "$1" \
  --role "$3" \
  "$2"

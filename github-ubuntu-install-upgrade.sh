#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="${REPO_OWNER:-vossie}"
REPO_NAME="${REPO_NAME:-DassieDrop}"
REPO_REF="${REPO_REF:-master}"
TMP_SCRIPT="$(mktemp)"

cleanup() {
  rm -f "${TMP_SCRIPT}"
}
trap cleanup EXIT

curl -fsSL "https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_REF}/scripts/github-ubuntu-install-upgrade.sh" -o "${TMP_SCRIPT}"
exec bash "${TMP_SCRIPT}" "$@"

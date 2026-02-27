#!/usr/bin/env bash
set -euo pipefail

CFG="/etc/litellm/config.yaml"
VENV="/opt/litellm/venv"

if [ -z "${DO_MODEL_API_KEY:-}" ]; then
  echo "missing DO_MODEL_API_KEY environment variable" >&2
  exit 1
fi

export DO_API_KEY="${DO_MODEL_API_KEY}"

exec "${VENV}/bin/litellm" --host 127.0.0.1 --port 4000 --config "${CFG}" --detailed_debug

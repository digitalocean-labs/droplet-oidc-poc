#!/usr/bin/env sh
set -x
set -e

SCRIPT_DIR="$(cd -P "$(dirname "${0}")" && pwd -P)"
REPO_DIR="${SCRIPT_DIR%/*}"
REPO_PARENT_DIR="${REPO_DIR%/*}"

. /app-venv/bin/activate

socket_dir="$(mktemp -d)"

export NODE_ENV=production
export PUBLIC_URL="${THIS_ENDPOINT}"
export HOST="127.0.0.1"
set +x
export COOKIE_SECRET="$(openssl rand -hex 64)"
echo 'export COOKIE_SECRET=...hidden...'
set -x
export STATUSPHERE_DIR="${REPO_PARENT_DIR}/statusphere-example-app"
export STATUSPHERE_DB_PATH="${STATUSPHERE_DIR}/atproto.db"
export STATUSPHERE_UNIX_SOCKET_PATH="${socket_dir}/statusphere.sock"
(
  cd "${STATUSPHERE_DIR}" \
  && DB_PATH="${STATUSPHERE_DB_PATH}" \
     node dist/index.js
) &

export UNIX_SOCKET_PATH="${socket_dir}/reverse_proxy_aiohttp.sock"
python -um workload_identity_oauth_reverse_proxy.reverse_proxy_aiohttp &

exec caddy run --config /app/Caddyfile

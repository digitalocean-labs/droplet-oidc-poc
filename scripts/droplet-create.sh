#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

USER_DATA="$("${SCRIPT_DIR}/make-cloud-init.py")"

curl -s -X POST -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $(doctl auth token)" \
  -d @<(
    jq -n \
      --arg ssh_keys "$(doctl compute ssh-key list -o json | jq -c '[.[].id]')" \
      --arg name "opencode-$(openssl rand -hex 4)" \
      --arg user_data "${USER_DATA}" \
      '{
          name: $name,
          region: "sfo3",
          image: "ubuntu-24-04-x64",
          ssh_keys: $ssh_keys | fromjson,
          size: "s-2vcpu-4gb",
          tags: ["oidc-sub:role:ex-create-model-keys"],
          user_data: $user_data
       }' \
  ) \
  "https://droplet-oidc.its1337.com/v2/droplets"

#!/usr/bin/env bash
#
# This is a cloud-init.sh script to initialize the opencode 1-click Droplet.
# It has to daemonize so that it can wait for the workload identity token to
# exist.
#
# It leverages the RBAC config defined within this repo to provision itself with
# a model api key via the droplet-oidc-poc workload identity reverse proxy.
#
# It also sets up opkssh so that the DO account owner can use google OAuth to
# ssh into the Droplet.
#
# TODO
# Finally, it enables one-shot prompting via an HTTP API. Protected by...
#
set -e
set -x

# Daemonize so that we can wait for the workload identity to exist and don't
# block it's creation
# if [ "x${IS_DAEMON_OPENCODE_CLOUD_INIT}" != "x1" ]; then
#   echo "[OPENCODE_CLOUD_INIT] Daemonizing..."
#   # First fork
#   (
#     # Create new session (prevents re-acquiring terminal)
#     setsid sleep 0 >/dev/null 2>&1
#
#     # Second fork - daemon
#     (
#       export IS_DAEMON_OPENCODE_CLOUD_INIT=1
#       exec bash "${0}"
#     ) & # Background the grandchild
#   ) & # Background the child and exit parent immediately
#   exit 0
# fi
#
# OUTFILE="/root/opencode-cloud-init.log"
# echo "[OPENCODE_CLOUD_INIT] Re-exec as daemon complete. Switching stdout/err to ${OUTFILE}..."
#
# # Close STDIN
# exec 0<&-
# exec 1>"${OUTFILE}"
# exec 2>&1

echo "[OPENCODE_CLOUD_INIT] Runnning OIDC based setup!!!"

# Grab vars from cloud-init deployment config
DOMAIN_NAME=$(cat /opt/opencode/bootstrap/deployment-config.json | jq -r '.domain_name')

useradd -m -s $(which bash) agent
echo "agent ALL=(ALL) NOPASSWD:ALL" | tee /etc/sudoers.d/90-cloud-init-users-agent
chmod 440 /etc/sudoers.d/90-cloud-init-users-agent

apt-get update
apt-get install -y -qq curl jq python3 python3-pip python3-venv

# OpenCode uses bun, so let's make sure it's installed
# apt-get install -y -qq nodejs npm
# npm install -g bun
# BUN_INSTALL=/opt/bun bun install -g opencode-ai
# sed -i -e 's#PATH="#PATH="/opt/bun/bin:#' /etc/environment
mkdir -pv /opt/opencode
curl -L 'https://github.com/anomalyco/opencode/releases/download/v1.2.15/opencode-linux-x64.tar.gz' | tar -zxv -C /opt/opencode
sed -i -e 's#PATH="#PATH="/opt/opencode:#' /etc/environment

mkdir -p /home/agent/.config/opencode/

# Install LiteLLM + uv into a dedicated litellm-owned virtualenv.
install -d -m 0755 -o litellm -g litellm /opt/litellm
install -d -m 0755 -o litellm -g litellm /var/lib/litellm
runuser -u litellm -- python3 -m venv /opt/litellm/venv
runuser -u litellm -- /opt/litellm/venv/bin/pip install --upgrade pip
runuser -u litellm -- /opt/litellm/venv/bin/pip install uv "litellm[proxy]"

install -D -m 0644 /opt/opencode/bootstrap/opencode.json /home/agent/.config/opencode/opencode.json
install -D -m 0644 /opt/opencode/bootstrap/litellm-config.yaml /etc/litellm/config.yaml
install -D -m 0755 /opt/opencode/bootstrap/litellm-start.sh /usr/local/bin/litellm-start.sh
install -D -m 0755 /opt/opencode/bootstrap/litellm-sanitize-proxy.py /usr/local/bin/litellm-sanitize-proxy.py
install -D -m 0644 /opt/opencode/bootstrap/litellm.service /etc/systemd/system/litellm.service
install -D -m 0644 /opt/opencode/bootstrap/litellm-sanitize-proxy.service /etc/systemd/system/litellm-sanitize-proxy.service

chown -R litellm:litellm /opt/litellm /var/lib/litellm
chown agent:agent -R /home/agent

# Install caddyserver
# TODO Configure exec of opencode endpoint
apt-get install -y -qq caddy

# --- Daemon Payload Starts Here ---

until test -f /root/secrets/digitalocean.com/serviceaccount/token; do
  sleep 0.1
done

URL=$(cat /root/secrets/digitalocean.com/serviceaccount/base_url)
TEAM_UUID=$(cat /root/secrets/digitalocean.com/serviceaccount/team_uuid)
ID_TOKEN=$(cat /root/secrets/digitalocean.com/serviceaccount/token)

SUBJECT="actx:${TEAM_UUID}:role:create-model-keys"

TOKEN=$(jq -n -c \
    --arg aud "api://DigitalOcean?actx=${TEAM_UUID}" \
    --arg sub "${SUBJECT}" \
    --arg ttl 300 \
    '{aud: $aud, sub: $sub, ttl: ($ttl | fromjson)}' | \
  curl -sf \
  -H "Authorization: Bearer ${ID_TOKEN}" \
  -d@- \
  "${URL}/v1/oidc/issue" \
  | jq -r .token)

# Setup opkssh based login
EMAIL=$(curl -sf \
  -H "Authorization: Bearer ${TOKEN}" \
  "${URL}/v2/account" \
  | jq -r .account.email)

wget -qO- "https://raw.githubusercontent.com/openpubkey/opkssh/main/scripts/install-linux.sh" | bash
opkssh add agent "${EMAIL}" google
opkssh add root "${EMAIL}" google
echo "[OPENCODE_CLOUD_INIT] Configured opkssh login"

# Provision model access key
MODEL_KEY_RESPONSE=$(jq -n -c \
    --arg name "opencode-$(curl -s https://icanhazip.com | sed -e 's/\./-/g')" \
    '{name: $name}' | \
  curl -sf \
  -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d@- \
  "${URL}/v2/gen-ai/models/api_keys")

MODEL_KEY=$(echo "${MODEL_KEY_RESPONSE}" | jq -r .api_key_info.secret_key)

printf 'DO_MODEL_API_KEY=%s\n' "${MODEL_KEY}" > /etc/default/litellm
chmod 640 /etc/default/litellm
chown root:litellm /etc/default/litellm
echo "[OPENCODE_CLOUD_INIT] Configured model key environment for litellm"

systemctl daemon-reload
systemctl enable --now litellm.service
systemctl enable --now litellm-sanitize-proxy.service
echo "[OPENCODE_CLOUD_INIT] Enabled litellm + sanitize proxy systemd services"

jq -n -c \
  --arg name "ai-$(openssl rand -hex 4).opencode" \
  --arg ipv4 "$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -vE '^10\.')" \
    '{type: "A",
      name: $name,
      data: $ipv4,
      priority: null,
      port: null,
      ttl: 1800,
      weight: null,
      flags: null,
      tag: null,
      }' | \
curl -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d@- \
  "${URL}/v2/domains/${DOMAIN_NAME}/records"

echo "[OPENCODE_CLOUD_INIT] Complete"

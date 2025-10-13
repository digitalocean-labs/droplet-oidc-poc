PORT_DIR=$(mktemp -d)
PORT_FILE="${PORT_DIR}/port.int"
python3 -c "import sys, socket, pathlib; public_key = sys.stdin.read().encode(); s = socket.socket(); s.bind(('0.0.0.0', 0)); pathlib.Path(sys.argv[-1]).write_text(str(s.getsockname()[1])); s.listen(1); c,_ = s.accept(); c.sendall(public_key); c.close(); s.close()" "${PORT_FILE}" < /etc/ssh/ssh_host_ed25519_key.pub &
until test -f "${PORT_FILE}"; do
    sleep 0.01
done
PORT=$(cat ${PORT_FILE})
SIG_JSON="$(echo -n "${PROVISIONING_TOKEN}" \
    | ssh-keygen -Y sign -n prove-sshd -f /etc/ssh/ssh_host_ed25519_key \
    | jq -c --arg port "${PORT}" --raw-input --slurp '{port: ($port | fromjson), sig: .}')"
PROVE_RESPONSE="$(curl -sfL \
    -H "Authorization: Bearer ${PROVISIONING_TOKEN}" \
    -d "${SIG_JSON}" \
    "${THIS_ENDPOINT}/v1/oidc/prove" \
    | jq -c)"

TOKEN="$(echo "${PROVE_RESPONSE}" | jq -r .token)"
REFRESH_TOKEN="$(echo "${PROVE_RESPONSE}" | jq -r .refresh_token)"

if [ -n "${TOKEN}" ] && [ "${TOKEN}" != "null" ]; then
    mkdir -p /root/secrets/digitalocean.com/serviceaccount/
    echo "${TOKEN}" > /root/secrets/digitalocean.com/serviceaccount/token
    echo "${REFRESH_TOKEN}" > /root/secrets/digitalocean.com/serviceaccount/refresh_token
    echo "${TEAM_UUID}" > /root/secrets/digitalocean.com/serviceaccount/team_uuid
    echo "${THIS_ENDPOINT}" > /root/secrets/digitalocean.com/serviceaccount/base_url
fi

UNIT_NAME="droplet-oidc-poc-token-refresh"
SCRIPT_NAME="droplet_oidc_poc_token_refresh.sh"
SCRIPT_INSTALL_DIR="/usr/local/bin"
LOG_FILE="/var/log/${UNIT_NAME}.log"
SYSTEMD_DIR="/etc/systemd/system"

SCRIPT_PATH="$SCRIPT_INSTALL_DIR/$SCRIPT_NAME"
SERVICE_FILE="$SYSTEMD_DIR/$UNIT_NAME.service"
TIMER_FILE="$SYSTEMD_DIR/$UNIT_NAME.timer"

cat > "$SCRIPT_PATH" << 'EOF'
#!/usr/bin/env bash
set -e

echo "Attempting Droplet OIDC PoC token refresh at $(date)"

URL=$(cat /root/secrets/digitalocean.com/serviceaccount/base_url)
REFRESH_TOKEN=$(cat /root/secrets/digitalocean.com/serviceaccount/refresh_token)

REFRESH_RESPONSE="$(curl -sfL \
    -X POST \
    -H "Authorization: Bearer ${REFRESH_TOKEN}" \
    "${URL}/v1/oidc/refresh" \
    | jq -c)"

TOKEN="$(jq -r .token <<<"${REFRESH_RESPONSE}")"
REFRESH_TOKEN="$(jq -r .refresh_token <<<"${REFRESH_RESPONSE}")"

if [ -n "${TOKEN}" ] && [ "${TOKEN}" != "null" ]; then
    echo "${TOKEN}" > /root/secrets/digitalocean.com/serviceaccount/token
    echo "${REFRESH_TOKEN}" > /root/secrets/digitalocean.com/serviceaccount/refresh_token
    echo "Droplet OIDC PoC token refresh successful at $(date)"
    exit 0
else
    echo "FAILED Droplet OIDC PoC token refresh at $(date)"
    exit 1
fi
EOF

chmod 700 "$SCRIPT_PATH"

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Service to refresh the Droplet OIDC PoC token
Wants=$UNIT_NAME.timer

[Service]
Type=oneshot
ExecStart=$SCRIPT_PATH
EOF

cat > "$TIMER_FILE" <<EOF
[Unit]
Description=Run Droplet OIDC PoC token refresh every minute

[Timer]
# Run 1 minute after boot, and every 5 minutes thereafter
OnBootSec=1min
OnUnitActiveSec=5min
Unit=$UNIT_NAME.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload

systemctl enable --now "$TIMER_FILE"

echo "Droplet OIDC PoC setup completed successfully"

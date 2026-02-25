#!/usr/bin/env bash
set -euo pipefail
set -x

mkdir -p policies/
mkdir -p roles/
mkdir -p droplet-roles/

cat <<'EOF' > policies/ex-create-model-keys.hcl
path "/v1/oidc/issue" {
  capabilities = ["create"]
  allowed_parameters = {
    "aud" = "api://DigitalOcean?actx={actx}"
    "sub" = "actx:{actx}:role:create-model-keys"
    "ttl" = 300
  }
}
EOF

cat <<'EOF' > droplet-roles/ex-create-model-keys.hcl
role "ex-create-model-keys" {
  aud      = "api://DigitalOcean?actx={actx}"
  sub      = "actx:{actx}:role:ex-create-model-keys"
  policies = ["ex-create-model-keys"]
}
EOF

cat <<'EOF' > policies/create-model-keys.hcl
path "/v2/gen-ai/models/api_keys" {
  capabilities = ["create"]
  allowed_parameters = {
    "name" = "opencode-*"
  }
}
EOF

cat <<'EOF' > roles/create-model-keys.hcl
role "create-model-keys" {
  aud      = "api://DigitalOcean?actx={actx}"
  sub      = "actx:{actx}:role:create-model-keys"
  policies = ["create-model-keys"]
}
EOF

# Define the FQDN of your deployed API proxy
export THIS_ENDPOINT="https://droplet-oidc.its1337.com"

mkdir -p "${HOME}/.local/scripts/"
tee "${HOME}/.local/scripts/git-credential-rbac-digitalocean.sh" <<'EOF'
#!/usr/bin/env bash

TOKEN=$(doctl auth token)

while IFS='=' read -r key value; do
  if [[ -n "$key" && -n "$value" ]]; then
    if [[ "$key" == "protocol" || "$key" == "host" ]]; then
      echo "$key=$value"
    fi
  fi
done

echo "username=token"
# https://git-scm.com/docs/git-credential documents how this style of
# script works, stdin / stdout is used for communication to / from git
# and the bash process executing this script. Since we always use the
# doctl local PAT for authentication to this PoC deployment, we don't need
# to add custom logic around if this host or if this protocol, we always
# use the token for the deployed FQDN (git config --global
# credential."${THIS_ENDPOINT}".helper)
echo "password=${TOKEN}"
EOF

chmod 700 "${HOME}/.local/scripts/git-credential-rbac-digitalocean.sh"
git config --global credential."${THIS_ENDPOINT}/_rbac/DigitalOcean/".helper \
  '!'"${HOME}/.local/scripts/git-credential-rbac-digitalocean.sh"
git branch -M main
git add .
git commit -sm "feat: configure model api key create access from droplet"
git remote add deploy "${THIS_ENDPOINT}"
git push -u deploy main

# View deployed config
git fetch --all && git show deploy/schema:rbac.json | jq

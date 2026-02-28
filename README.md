# opencode

First deploy https://github.com/digitalocean-labs/droplet-oidc-poc as an App
Platform app.

Make sure you have `uv` installed and in your path

Clone this branch

```
git clone -b opencode-rbac https://github.com/digitalocean-labs/droplet-oidc-poc
```

Run setup using a domain you own and has already been added to your DO account

```
DOMAIN_NAME=example.com bash scripts/setup.sh
```

Create the droplet and wait for it to go live (this `tail`s the logs):

```bash
DROPLET_ID=$(bash scripts/droplet-create.sh | jq -r .droplet.id) && echo $DROPLET_ID && until doctl compute ssh "${DROPLET_ID}" --ssh-command 'echo hi'; do sleep 0.1; done; doctl compute ssh "${DROPLET_ID}" --ssh-command 'tail -F /var/log/opencode-cloud-init.log'
```

Setup `opkssh`

- https://github.com/openpubkey/opkssh?tab=readme-ov-file#getting-started

```
opkssh login -i ~/opkssh_server_group1
```

SSH in using your Google sign-in enabled DO account:

- `INSTANCE_NAME` can be seen in the output of the Droplet spin up logs you ran
  `tail` on above.

```
ssh -o IdentitiesOnly=yes -o IdentityFile="${HOME}/opkssh_server_group1" -t \
  "agent@${INSTANCE_NAME}.opencode.${DOMAIN_NAME}" tmux
```

Run opencode and ask it to do something (Model API key already configured)

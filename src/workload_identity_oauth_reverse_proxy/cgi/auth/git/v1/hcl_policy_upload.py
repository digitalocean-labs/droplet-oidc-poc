import os
import sys
import atexit
import base64
import pathlib
import tempfile
import subprocess
import urllib.error

from ..... import do_api
from ..... import hcl_policy
from ..... import cgi_helper
from ..... import oidc_helper
from ..... import rbac_helper
from ..... import database
from .....common import PATH_INFO


# We figure out the repo from the token but allow paths
# for client git-credential helper side to select token
# for API + identifier
if PATH_INFO.startswith("/_rbac/"):
    PATH_INFO = "/" + "/".join(PATH_INFO.split("/")[4:])
    os.environ["PATH_INFO"] = PATH_INFO

# Grab the token from the HTTP Basic auth info
token, _ = cgi_helper.get_token()
token = base64.b64decode(token).decode().split(":", maxsplit=1)[1]
token_is_oidc = bool(token.count(".") == 2)

# Lookup the account asscociated with the token
if not token_is_oidc:
    api = "DigitalOcean"
    actx = do_api.get_team_uuid(token)
    # Ensure team member has Droplet create permission. We test this by attempting
    # to create a droplet with an invalid region. A "422 Unprocessable Entity"
    # error confirms the token is valid for the create action. Any other error
    # (e.g., 401 Unauthorized) means the check fails.
    has_droplet_create = False
    try:
        test_payload = {
            "name": "temp-auth-check-droplet",
            # This is a minimal but invalid region to test for create permissions
            "region": "invalid-region-for-auth-check",
            "size": "s-1vcpu-1gb",
            "image": "ubuntu-24-04-x64",
        }
        do_api.do_droplet_create(token, test_payload)
    except urllib.error.HTTPError as e:
        import snoop, json
        snoop.pp(e, json.loads(e.read()))
        if e.code == 422:
            has_droplet_create = True
    if not has_droplet_create:
        sys.exit(1)
else:
    # Validate token against self as issuer
    oidc_token = oidc_helper.OIDCToken.validate(token)
    api = oidc_token.api
    actx = oidc_token.actx
    # For when no policy exists yet
    if (
        oidc_token.claims.get("rbac_config_api", "") == api
        and oidc_token.claims.get("rbac_config_id", "") == oidc_token.actx
    ):
        pass
    else:
        # Load policies for team
        rbac_config = rbac_helper.load_config(oidc_token.api, oidc_token.actx)
        # Check if request is allowed by role and polices
        permissions = hcl_policy.check_permissions(
            *rbac_config,
            oidc_token.claims,
            path="/_rbac",
            capability="write",
            req_json=None,
        )
        if not permissions.allow:
            sys.exit(1)

# Create a temporary directory for the git repo
tempdir = tempfile.TemporaryDirectory()
atexit.register(tempdir.cleanup)
local_repo_path = pathlib.Path(tempdir.name, f"{actx}.git")

# If repo doesn't exist in DB, initialize a new one
if not database.restore_rbac_git_repo_to_path(api, actx, local_repo_path):
    local_repo_path.mkdir(parents=True)
    subprocess.check_call(
        [
            "git",
            "init",
            "--initial-branch=main",
            "--bare",
            str(local_repo_path.resolve()),
        ],
        cwd=str(local_repo_path.parent),
        stdout=subprocess.DEVNULL,
    )
# Ensure settings are corrent to receive git push
proc = subprocess.check_call(
    ["git", "config", "http.receivepack", "true"],
    cwd=str(local_repo_path),
)
subprocess.check_call(
    ["git", "config", "receive.advertisePushOptions", "true"],
    cwd=str(local_repo_path),
)
subprocess.check_call(
    ["rm", "-rf", "hooks"],
    cwd=str(local_repo_path),
)

env = os.environ.copy()
env.update(
    {
        "GIT_PROJECT_ROOT": ".",
        "GIT_HTTP_EXPORT_ALL": "1",
    }
)

# Prepare the subprocess to run git http-backend
subprocess.check_call(
    ["git", "http-backend"],
    cwd=str(local_repo_path),
    env=env,
    stdin=sys.stdin,
    stdout=sys.stdout,
    stderr=sys.stderr,
)

# Only on push
if "git-receive-pack" not in PATH_INFO:
    sys.exit(0)

# Do a build of the JSON Schema used for validation this let's users check that
# their policy was successfully adapted
with tempfile.TemporaryDirectory() as tempdir:
    tempdir_path = pathlib.Path(tempdir)
    hcl_path = tempdir_path.joinpath("hcl")
    schema_path = tempdir_path.joinpath("schema")
    # Ensure we have a directory for the main branch
    subprocess.check_call(
        [
            "git",
            "clone",
            "--depth=1",
            "-b",
            "main",
            str(local_repo_path),
            str(hcl_path),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Find out what the latest commit to main was
    main_head_commit_sha = (
        subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=str(local_repo_path),
        )
        .decode()
        .strip()
    )
    # Ensure we have a directory for the schema branch
    if (
        subprocess.run(
            ["git", "clone", "-b", "schema", str(local_repo_path), str(schema_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        != 0
    ):
        schema_path.mkdir()
        for cmd in [
            ["git", "init", "--initial-branch=schema"],
            ["git", "remote", "add", "origin", str(local_repo_path)],
        ]:
            subprocess.check_call(
                cmd,
                cwd=str(schema_path),
            )
    # Run the schema generation
    rbac_json_path = schema_path.joinpath("rbac.json")
    hcl_policy.serialize_configuration_from_hcl_directory_to_file(
        hcl_path,
        rbac_json_path,
    )
    # NOTE HACK Support for {actx} to team UUID
    rbac_json_path.write_text(
        rbac_json_path.read_text().replace("{actx}", str(actx)),
    )
    # Commit and save the result
    for cmd in [
        ["git", "config", "user.name", "Automated Schema Builder"],
        ["git", "config", "user.email", "build@local.host"],
        ["git", "add", "rbac.json"],
        ["git", "commit", "-sm", main_head_commit_sha],
        ["git", "push", "-u", "-f", "origin", "schema"],
    ]:
        subprocess.run(
            cmd,
            cwd=str(schema_path),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

# Store tempdir for rbac in database on push
database.save_rbac_git_repo_from_path(api, actx, local_repo_path)

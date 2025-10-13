import os
import uuid
import pathlib
import tempfile
import functools
import subprocess

from . import cgi_helper
from . import hcl_policy
from . import oidc_helper
from . import database

import snoop

@functools.lru_cache(maxsize=None)
def load_config(api: str, actx: str) -> dict:
    """
    Load configuration for a given API and authentication context (actx).
    For DigitalOcean, actx is a team_uuid.
    """
    with tempfile.TemporaryDirectory() as tempdir:
        # For DigitalOcean, actx is a team_uuid.
        # For other APIs, it could be something else.
        local_repo_path = pathlib.Path(tempdir, f"{actx}.git")
        snoop.pp(api, actx)
        if not database.restore_rbac_git_repo_to_path(api, actx, local_repo_path):
            raise FileNotFoundError(f"No RBAC repo found for actx {actx}")

        # Ensure we have a directory for the schema branch
        schema_path = pathlib.Path(tempdir, "schema")
        subprocess.check_call(
            ["git", "clone", "-b", "schema", str(local_repo_path), str(schema_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        rbac_contents = schema_path.joinpath("rbac.json").read_text()
    return hcl_policy.deserialize_configuration(rbac_contents)


def get_issuers(api: str, actx: str) -> list[str]:
    roles, _, _ = load_config(api, actx)
    return filter(
        bool,
        [role.get("definition", {}).get("iss", None) for role in roles.values()],
    )


def raise_if_unauthorized(
    token: str,
    path: str,
    capability: str,
    query_params: dict | None = None,
    req_json: dict | None = None,
) -> oidc_helper.OIDCToken:
    if query_params is not None:
        if req_json is None:
            req_json = {}
        req_json["?"] = query_params
    # Validate token against approved issuers
    oidc_token = oidc_helper.OIDCToken.validate(token, get_issuers=get_issuers)
    # Load policies for team
    rbac_config = load_config(oidc_token.api, oidc_token.actx)
    # Check if request is allowed by role and polices
    permissions = hcl_policy.check_permissions(
        *rbac_config,
        oidc_token.claims,
        path=path,
        capability=capability,
        req_json=req_json,
    )
    if not permissions.allow:
        raise cgi_helper.UnauthorizedException(permissions.error_msg)
    return oidc_token

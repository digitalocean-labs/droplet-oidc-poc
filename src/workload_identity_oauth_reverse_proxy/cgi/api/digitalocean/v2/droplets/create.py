import sys
import json

from ...... import do_api
from ...... import cgi_helper
from ...... import rbac_helper
from ...... import oauth_helper
from ...... import provisioning
from ......common import PATH_INFO


@cgi_helper.json_response
def cgi_handler() -> dict:
    global PATH_INFO

    request_obj = json.load(sys.stdin)

    # Pass token through to upstream if not an OIDC token
    token, token_is_oidc = cgi_helper.get_token()
    if not token_is_oidc:
        team_uuid = do_api.get_team_uuid(token)
        team_token = token
    else:
        oidc_token = rbac_helper.raise_if_unauthorized(
            token, PATH_INFO, "create", req_json=request_obj
        )
        # Use team token for upstream API calls
        # NOTE Enable Droplet create OAuth scope if you want this to work
        # Be very careful about the tags you allow to be created if you do this
        # due to them turning into OIDC roles (detailed in blog post)
        team_uuid = oidc_token.actx
        team_token = oauth_helper.retrieve_oauth_token(team_uuid)

    provisioning_data = provisioning.ProvisioningData.create(
        team_uuid,
        request_obj.get("user_data", None),
    )
    request_obj["user_data"] = provisioning_data.user_data
    # Create the Droplet
    droplet_create_reponse = do_api.do_droplet_create(team_token, request_obj)
    # Ensure nonce can be used to provision workload identity token
    provisioning_data.associate_with_droplet(
        droplet_create_reponse.get("droplet", {}).get("id", 0),
    )
    return droplet_create_reponse


if __name__ == "__main__":
    cgi_handler()

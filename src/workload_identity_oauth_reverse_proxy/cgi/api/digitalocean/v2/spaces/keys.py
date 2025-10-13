import sys
import json

from ...... import do_api
from ...... import cgi_helper
from ...... import rbac_helper
from ...... import oauth_helper
from ......common import PATH_INFO


@cgi_helper.json_response
def cgi_handler() -> dict:
    global PATH_INFO

    request_obj = json.load(sys.stdin)

    # Pass token through to upstream if not an OIDC token
    token, token_is_oidc = cgi_helper.get_token()
    if not token_is_oidc:
        team_token = token
    else:
        oidc_token = rbac_helper.raise_if_unauthorized(
            token, PATH_INFO, "create", req_json=request_obj
        )
        # Use team token for upstream API calls
        team_token = oauth_helper.retrieve_oauth_token(oidc_token.team_uuid)

    # Do request to upstream API
    return do_api.do_spaces_keys_create(
        team_token,
        request_obj,
    )


if __name__ == "__main__":
    cgi_handler()

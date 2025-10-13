import sys
import json

from ..... import cgi_helper
from ..... import rbac_helper
from ..... import oidc_helper
from .....common import PATH_INFO


@cgi_helper.json_response
def cgi_handler():
    global PATH_INFO

    request_obj = json.load(sys.stdin)

    token, _token_is_oidc = cgi_helper.get_token()

    oidc_token = rbac_helper.raise_if_unauthorized(
        token, PATH_INFO, "create", req_json=request_obj
    )

    if "id-token-refresh" in request_obj:
        raise cgi_helper.UnauthorizedException(
            "tokens may not contain id-token-refresh claim",
        )

    return {
        "token": oidc_helper.OIDCToken.create(
            oidc_token.actx,
            request_obj,
        ).as_string
    }


if __name__ == "__main__":
    cgi_handler()

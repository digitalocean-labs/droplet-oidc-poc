from ...... import do_api
from ...... import cgi_helper
from ...... import rbac_helper
from ...... import oauth_helper
from ......common import PATH_INFO, QUERY_PARAMS


@cgi_helper.json_response
def cgi_handler() -> dict:
    database_uuid = None
    if PATH_INFO.startswith("/v2/databases/"):
        database_uuid = PATH_INFO.split("databases/")[1].strip()

    # Pass token through to upstream if not an OIDC token
    token, token_is_oidc = cgi_helper.get_token()
    if not token_is_oidc:
        team_token = token
    else:
        kwargs = {}
        if database_uuid is None:
            kwargs["query_params"] = QUERY_PARAMS
        oidc_token = rbac_helper.raise_if_unauthorized(
            token,
            PATH_INFO,
            "read",
            **kwargs,
        )
        # Use team token for upstream API calls
        team_token = oauth_helper.retrieve_oauth_token(oidc_token.team_uuid)

    # Do request to upstream API
    if database_uuid is not None:
        return do_api.do_databases_get_single(
            team_token,
            database_uuid=database_uuid,
        )
    return do_api.do_databases_list(
        team_token,
        query_params=QUERY_PARAMS,
    )


if __name__ == "__main__":
    cgi_handler()

from ... import cgi_helper
from ... import jwt_helper


@cgi_helper.json_response
def cgi_handler():
    return {
        "issuer": jwt_helper.JWT_ISSUER_URL,
        "jwks_uri": f"{jwt_helper.JWT_ISSUER_URL}/.well-known/jwks",
        "response_types_supported": ["id_token"],
        "claims_supported": ["sub", "aud", "exp", "iat", "iss"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid"],
    }


if __name__ == "__main__":
    cgi_handler()

import sys
import json

from ..... import cgi_helper
from ..... import oidc_helper
from ..... import provisioning


@cgi_helper.json_response
def cgi_handler():
    request_obj = json.load(sys.stdin)

    token, _token_is_oidc = cgi_helper.get_token()

    oidc_token, droplet = provisioning.validate(
        token, request_obj["sig"], request_obj["port"]
    )
    if droplet is None:
        return {"valid": False}

    subject = ":".join(
        [
            f"actx:{oidc_token.actx}",
        ]
        + [
            tag.split(":", maxsplit=1)[1]
            for tag in droplet["tags"]
            if tag.startswith("oidc-sub:") and tag.count(":") == 2 and tag.split(":")[1] != "actx"
        ]
    )

    claims = {"sub": subject, "droplet_id": droplet["id"]}
    import snoop
    snoop.pp(claims)

    refresh_claims = {
        "sub": f"actx:{oidc_token.actx}:role:id-token-refresh",
        "id-token-refresh": True,
        "droplet_id": droplet["id"],
        "ttl": 60 * 15,
    }
    snoop.pp(refresh_claims)

    return {
        "token": oidc_helper.OIDCToken.create(oidc_token.actx, claims).as_string,
        "refresh_token": oidc_helper.OIDCToken.create(oidc_token.actx, refresh_claims).as_string,
    }


if __name__ == "__main__":
    cgi_handler()

from ... import cgi_helper
from ... import jwt_helper


@cgi_helper.json_response
def cgi_handler():
    key = jwt_helper.JWT_SIGNING_KEY_PRIVATE
    return {
        "keys": [
            {
                **key.export_public(as_dict=True),
                "use": "sig",
                "kid": key.thumbprint(),
            }
        ]
    }


if __name__ == "__main__":
    cgi_handler()

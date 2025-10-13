import jwcrypto.jwk

from .common import THIS_ENDPOINT
from . import database


JWT_ISSUER_URL = THIS_ENDPOINT
JWT_ALGORITHM = "RS256"

# Load or generate private key
JWT_SIGNING_KEY_PRIVATE_PEM = database.get_jwk_pem(JWT_ISSUER_URL)
generate_jwk = bool(JWT_SIGNING_KEY_PRIVATE_PEM is None)
if generate_jwk:
    JWT_SIGNING_KEY_PRIVATE = jwcrypto.jwk.JWK.generate(kty="RSA", size=4096)
else:
    JWT_SIGNING_KEY_PRIVATE = jwcrypto.jwk.JWK.from_pem(
        JWT_SIGNING_KEY_PRIVATE_PEM.encode(), password=None
    )

JWT_SIGNING_KEY_PUBLIC_PEM = JWT_SIGNING_KEY_PRIVATE.export_to_pem()
JWT_SIGNING_KEY_PRIVATE_PEM = JWT_SIGNING_KEY_PRIVATE.export_to_pem(
    private_key=True, password=None
)

# Save key to database if generated (first call)
if generate_jwk:
    database.save_jwk_pem(JWT_ISSUER_URL, JWT_SIGNING_KEY_PRIVATE_PEM.decode())

import os
import lzma
import base64
import datetime
import pathlib
import hashlib
import secrets
import subprocess
import json
import math
import random
import contextlib
import string
import time
from typing import Dict, Optional, Any
from urllib.parse import urlparse, urlunparse

import snoop

import aiohttp
from pydantic import BaseModel
from aiohttp import web

# Replaced jwskate with jwcrypto for key management, signing, and utility functions
from jwcrypto import jwk, jws, common

# A simple in-memory store for nonces. In a real application, this might
# be a Redis-backed or file-backed store for persistence.
nonce_storage: Dict[str, str] = {}


class OAuthSession(BaseModel):
    aud: str
    sub: str
    iss: str
    scope: str
    refresh_token: str
    access_token: str
    token_type: str
    expires_at: str
    jwk: dict


def build_htu(url: str) -> str:
    """
    Strips the query and fragment from a URL to create the 'htu' (HTTP URI) claim.
    See: https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2-4.6
    """
    parsed = urlparse(url)
    # Reconstruct the URL with only scheme, netloc, and path
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


def build_proof(
    key: jwk.JWK,
    alg: str,
    htm: str,
    htu: str,
    nonce: Optional[str] = None,
    ath: Optional[str] = None,
) -> str:
    # Export the public part of the key to be embedded in the JWT header
    public_jwk_dict = key.export_public(as_dict=True)
    now = math.floor(time.time())

    payload = {
        "iat": now,
        "jti": secrets.token_hex(nbytes=32),
        "htm": htm,  # HTTP Method
        "htu": htu,  # HTTP URI
    }
    if nonce:
        payload["nonce"] = nonce
    if ath:
        payload["ath"] = ath  # Access Token Hash

    # The protected header contains metadata about the token
    protected_header = {
        "alg": alg,
        "typ": "dpop+jwt",
        "jwk": public_jwk_dict,
    }

    snoop.pp(protected_header, payload)

    # Serialize the payload to a string, then encode to bytes for signing
    payload_str = json.dumps(payload)
    jws_obj = jws.JWS(payload_str.encode("utf-8"))

    # Sign the JWS with the private key
    jws_obj.add_signature(key, protected=protected_header)

    return jws_obj.serialize(compact=True)


async def is_use_dpop_nonce_error(response: aiohttp.ClientResponse) -> bool:
    # Check for Resource Server error (e.g., a protected API)
    if response.status == 401:
        www_auth = response.headers.get("www-authenticate", "")
        if www_auth.lower().startswith("dpop") and (
            'error="use_dpop_nonce"' in www_auth
            or 'error="invalid_dpop_proof"' in www_auth
        ):
            return True

    return False


def sha256_base64url(input_str: str) -> str:
    """Computes a SHA-256 hash and encodes it as Base64URL."""
    digest = hashlib.sha256(input_str.encode("utf-8")).digest()
    # Use jwcrypto's implementation for Base64URL encoding
    return common.base64url_encode(digest)


class DPoPClientSession:
    """
    A wrapper around aiohttp.ClientSession that implements the DPoP
    authentication flow, including automatic handling of nonce challenges.
    """

    def __init__(self, key: jwk.JWK, alg: str = "ES256K", **kwargs):
        if not isinstance(key, jwk.JWK) or not key.has_private:
            raise ValueError(
                "Provided JWK must be a private jwcrypto.jwk.JWK to be used for signing."
            )

        self.key = key
        self.alg = alg
        self.session = aiohttp.ClientSession(**kwargs)

    @contextlib.asynccontextmanager
    async def request(
        self, method: str, url: str, **kwargs: Any
    ) -> aiohttp.ClientResponse:
        """Performs a request with DPoP, handling nonce retries."""
        # --- First Request ---
        url_str = str(url)
        parsed_url = urlparse(url_str)
        origin = f"{parsed_url.scheme}://{parsed_url.netloc}"

        initial_nonce = nonce_storage.get(origin)
        snoop.pp(initial_nonce)

        headers = kwargs.get("headers", {})
        auth_header = headers.get("Authorization", self.session.headers.get("Authorization", ""))
        snoop.pp(auth_header)
        ath = None
        if auth_header.lower().startswith("dpop "):
            access_token = auth_header.split(" ", 1)[1]
            ath = sha256_base64url(access_token)

        initial_proof = build_proof(
            key=self.key,
            alg=self.alg,
            htm=method.upper(),
            htu=build_htu(url_str),
            nonce=initial_nonce,
            ath=ath,
        )
        headers["DPoP"] = initial_proof
        kwargs["headers"] = headers

        async with contextlib.AsyncExitStack() as astack:
            response = await astack.enter_async_context(
                self.session.request(method, url, **kwargs),
            )

            # --- Handle Response from Server ---
            snoop.pp(dict(response.headers))
            next_nonce = response.headers.get("dpop-nonce")
            if next_nonce and next_nonce != initial_nonce:
                nonce_storage[origin] = next_nonce

            should_retry = await is_use_dpop_nonce_error(response)
            snoop.pp(should_retry)
            if not should_retry:
                yield response
                return

            # --- Second (Retry) Request ---
            print("DPoP: Server requested a new nonce. Retrying request...")
            # Release the first response to free up the connection
            response.release()

            retry_proof = build_proof(
                key=self.key,
                alg=self.alg,
                htm=method.upper(),
                htu=build_htu(url_str),
                nonce=next_nonce,
                ath=ath,
            )
            headers["DPoP"] = retry_proof
            kwargs["headers"] = headers

            snoop.pp(headers)

            response_after_retry = await astack.enter_async_context(
                self.session.request(method, url, **kwargs),
            )

            final_nonce = response_after_retry.headers.get("dpop-nonce")
            if final_nonce and final_nonce != next_nonce:
                nonce_storage[origin] = final_nonce

            yield response_after_retry

    # Convenience methods for GET, POST, etc.
    @contextlib.asynccontextmanager
    async def get(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        async with self.request("GET", url, **kwargs) as response:
            yield response

    @contextlib.asynccontextmanager
    async def post(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        async with self.request("POST", url, **kwargs) as response:
            yield response

    async def __aenter__(self):
        self.session = await self.session.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.close()


async def main():
    user_did = "did:plc:3wh3syflsnsokc7xjdj7xilu"
    oauth_session = OAuthSession.model_validate_json(
        subprocess.check_output(
            [
                "node",
                "get-token-cli.js",
                user_did,
            ],
            env={
                **os.environ,
                **{
                    "PUBLIC_URL": "https://statusphere.alice.chadig.com",
                    "DB_PATH": "atproto.db",
                },
            },
            cwd=str(pathlib.Path(__file__).parent.resolve()),
        ).decode()
    )
    snoop.pp(oauth_session)

    # 1. Generate a new signing key
    key = jwk.JWK.from_json(json.dumps(oauth_session.jwk))
    print("Generated Signing Key (Public Part):", key.export(private_key=False))

    ascii_string = pathlib.Path(__file__).read_text()
    # ascii_string = base64.b85encode(lzma.compress(ascii_string.encode('ascii'))).decode('ascii')

    for i in range(300, len(ascii_string), 300):
        text = ascii_string[i - 300:i]

        post_data = {
            "repo": user_did,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": text,
                "createdAt": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            },
        }

        snoop.pp(post_data)

        # 3. Make a request using the DPoPClientSession
        async with DPoPClientSession(key=key, alg="ES256K") as session:
            print("\nMaking initial request that will trigger a nonce challenge...")
            headers = {
                "Authorization": f"DPoP {oauth_session.access_token}",
                "Content-Type": "application/json",
            }
            url = f"{oauth_session.aud}xrpc/com.atproto.repo.createRecord"
            snoop.pp(url, headers)
            async with session.post(
                url,
                json=post_data,
                headers=headers,
            ) as response:
                print("\n--- Final Result ---")
                print("Status Code:", response.status)
                print("Response JSON:", await response.json())
                print(
                    "Nonce stored for origin 'http://127.0.0.1:9090':",
                    nonce_storage.get("http://127.0.0.1:9090"),
                )


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())

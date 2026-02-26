#!/usr/bin/env python3
r"""
- https://intel.github.io/dffml/main/examples/integration.html?highlight=cgi+bin
- https://docs.digitalocean.com/reference/api/digitalocean/
- https://docs.digitalocean.com/reference/api/oauth/#client-application-flow
"""
import os
import json
import uuid
import secrets
import urllib.parse
import urllib.request

from ..... import do_api
from ..... import oauth_helper
from ..... import landing_page
from .....common import THIS_ENDPOINT, QUERY_PARAMS, UPSTREAM_API_URL


DIGITALOCEAN_OAUTH_CLIENT_ID = os.getenv(
    "DIGITALOCEAN_OAUTH_CLIENT_ID",
    default=None,
)
DIGITALOCEAN_OAUTH_CLIENT_SECRET = os.getenv(
    "DIGITALOCEAN_OAUTH_CLIENT_SECRET",
    default=None,
)


def cgi_handler():
    if DIGITALOCEAN_OAUTH_CLIENT_ID is None or DIGITALOCEAN_OAUTH_CLIENT_SECRET is None:
        print("Content-Type: text/html")
        print()
        print(
            "<h1>DIGITALOCEAN_OAUTH_CLIENT_ID and DIGITALOCEAN_OAUTH_CLIENT_SECRET environment variables must be set</h1>"
        )
    elif "code" not in QUERY_PARAMS:
        readme_markdown = landing_page.get_readme_markdown(__package__)
        readme_markdown = landing_page.set_this_endpoint(
            readme_markdown,
            THIS_ENDPOINT,
        )
        html_content = landing_page.convert_readme_to_html(readme_markdown)
        html_content = landing_page.add_consent_button(
            html_content,
            create_authorize_url(),
        )
        html_content = landing_page.bootstrapify_html(html_content)

        print("Content-Type: text/html")
        print()
        print(html_content)
    else:
        # Request an OAuth token after client secret OAuth authorize with
        # code flow (aka Web Application flow)
        code = QUERY_PARAMS["code"]
        base_url = "https://cloud.digitalocean.com/v1/oauth/token"
        params = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": DIGITALOCEAN_OAUTH_CLIENT_ID,
            "client_secret": DIGITALOCEAN_OAUTH_CLIENT_SECRET,
        }

        # Encode the parameters
        query_string = urllib.parse.urlencode(params)

        # Construct the full URL
        final_url = f"{base_url}?{query_string}&redirect_uri={THIS_ENDPOINT}/auth/digitalocean/v1/callback"

        headers = {
            "Content-Type": "application/json",
        }

        request = urllib.request.Request(
            final_url,
            method="POST",
            headers=headers,
        )

        with urllib.request.urlopen(request) as response:
            response_content = response.read()

        response_dict = json.loads(response_content)

        # Get account info to associate token with team
        token = response_dict["access_token"]
        team_uuid = do_api.get_team_uuid(token)

        oauth_helper.store_oauth_token(team_uuid, token)

        print("Status: 307 Temporary Redirect")
        print(f"Location: /#policies-and-roles")
        print()


def create_authorize_url():
    state = secrets.token_hex(nbytes=64)

    base_url = "https://cloud.digitalocean.com/v1/oauth/authorize"
    params = {
        "response_type": "code",
        "client_id": DIGITALOCEAN_OAUTH_CLIENT_ID,
        "scope": "read write",
        "state": state,
    }

    # Encode the parameters
    query_string = urllib.parse.urlencode(params)

    # Construct the full URL
    final_url = f"{base_url}?{query_string}&redirect_uri={THIS_ENDPOINT}/auth/digitalocean/v1/callback"

    return final_url


if __name__ == "__main__":
    cgi_handler()

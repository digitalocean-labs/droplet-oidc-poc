import json
import uuid
import urllib.request

from .common import UPSTREAM_API_URL, PATH_INFO


def get_team_uuid(token: str) -> uuid.UUID:
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    path = "/v2/account"
    request = urllib.request.Request(
        f"{UPSTREAM_API_URL}{path}",
        headers=headers,
    )

    with urllib.request.urlopen(request) as response:
        response_content = response.read()

    response_dict = json.loads(response_content)
    return uuid.UUID(response_dict["account"]["team"]["uuid"])


def do_droplet_get(token: str, droplet_id: str) -> dict:
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    path = f"/v2/droplets/{droplet_id}"
    request = urllib.request.Request(
        f"{UPSTREAM_API_URL}{path}",
        headers=headers,
    )
    with urllib.request.urlopen(request) as response:
        response_content = response.read()
        return json.loads(response_content)["droplet"]


def do_droplet_create(token: str, request_obj: dict) -> dict:
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    headers["Host"] = "api.digitalocean.com"
    path = "/v2/droplets"
    request = urllib.request.Request(
        f"{UPSTREAM_API_URL}{path}",
        headers=headers,
    )
    request_bytes = json.dumps(request_obj).encode()
    with urllib.request.urlopen(request, data=request_bytes) as response:
        response_content = response.read()
        return json.loads(response_content)


def do_databases_get_single(team_token, *, database_uuid):
    headers = {
        "Authorization": f"Bearer {team_token}",
    }
    path = f"/v2/databases/{database_uuid}"
    request = urllib.request.Request(
        f"{UPSTREAM_API_URL}{path}",
        headers=headers,
    )
    with urllib.request.urlopen(request) as response:
        response_content = response.read()
        response_dict = json.loads(response_content)
        return response_dict


def do_databases_list(team_token, *, query_params):
    headers = {
        "Authorization": f"Bearer {team_token}",
    }
    path = "/v2/databases"
    params = urllib.parse.urlencode(query_params)
    request = urllib.request.Request(
        f"{UPSTREAM_API_URL}{path}?{params}",
        headers=headers,
    )
    with urllib.request.urlopen(request) as response:
        response_content = response.read()
        response_dict = json.loads(response_content)
        return response_dict


def do_spaces_keys_create(spaces_token: str, request_obj: dict) -> dict:
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {spaces_token}",
    }
    request = urllib.request.Request(
        f"{UPSTREAM_API_URL}{PATH_INFO}",
        headers=headers,
        method="POST",
    )

    request_bytes = json.dumps(request_obj).encode()

    with urllib.request.urlopen(request, data=request_bytes) as response:
        response_content = response.read()
        return json.loads(response_content)

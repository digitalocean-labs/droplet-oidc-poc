import os
import sys
import http
import json
import shutil
import functools
import traceback
import urllib.error


class UnauthorizedException(Exception):
    pass


def get_token() -> tuple[str, bool]:
    token = os.environ.get("HTTP_AUTHORIZATION", "Bearer 0").split()[1]
    if token == "0":
        raise UnauthorizedException(
            "Missing required header: Authorization: Bearer {token}"
        )
    return token, bool(token.count(".") == 2)


def json_response(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            response = func(*args, **kwargs)
        except urllib.error.HTTPError as error:
            print(f"Status: {error.code} {error.reason}")
            print(str(error.headers), end="")
            shutil.copyfileobj(error.fp, sys.stdout.buffer)
            return
        except UnauthorizedException as e:
            status_code = http.HTTPStatus.UNAUTHORIZED
            traceback.print_exc(file=sys.stderr)
            response = {"id": "unauthorized", "message": str(e)}
        except Exception as e:
            status_code = http.HTTPStatus.INTERNAL_SERVER_ERROR
            traceback.print_exc(file=sys.stderr)
            response = {"id": "server_error", "message": "Unexpected server-side error"}
        else:
            status_code = http.HTTPStatus.OK
        print(f"Status: {status_code}")
        print("Content-Type: application/json")
        print()
        print(json.dumps(response))

    return wrapper

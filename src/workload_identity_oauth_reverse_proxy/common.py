import os
import urllib.parse


PATH_INFO = os.getenv("PATH_INFO", default="")
QUERY_PARAMS = dict(urllib.parse.parse_qsl(os.getenv("QUERY_STRING", default="")))
THIS_ENDPOINT = os.getenv("THIS_ENDPOINT", default="http://localhost:8080")
UPSTREAM_API_URL = os.getenv("UPSTREAM_API_URL", default="https://api.digitalocean.com")

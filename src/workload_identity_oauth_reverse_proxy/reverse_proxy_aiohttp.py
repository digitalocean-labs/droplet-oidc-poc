import os
import sys
import json
import socket
import asyncio
import pathlib
import traceback
import subprocess
import contextlib
from unittest.mock import patch
from http import HTTPStatus
from urllib.parse import urlparse, urlencode, urljoin
from contextlib import asynccontextmanager, ExitStack

from aiohttp import web
from aiohttp import client
from aiohttp.test_utils import AioHTTPTestCase
import aiohttp.client_exceptions
import aiohttp

import logging

import snoop

from jwcrypto import jwk

from . import do_api
from . import cgi_helper
from . import rbac_helper
from . import oauth_helper
from .common import UPSTREAM_API_URL, THIS_ENDPOINT
from .apis.ATProto.dpop import OAuthSession, DPoPClientSession


# From StackOverflow: https://stackoverflow.com/a/52403071
class ReverseProxyHandlerContext(object):
    def __init__(
        self,
        parent: "ReverseProxyHandler",
        *,
        hostname: str = None,
        address: str = "127.0.0.1",
        unix_socket_path: str = None,
        port: int = 0,
    ) -> None:
        """
        Hostname must be set in order to resolve subdomains
        """
        self.parent = parent
        self.hostname = "localhost" if hostname is None else hostname
        self.unix_socket_path = unix_socket_path
        self.address = address
        self.port = port
        self.upstream = {}
        self.logger = logging.getLogger(__package__).getChild(self.__class__.__qualname__)

    async def wsforward(self, ws_from, ws_to):
        async for msg in ws_from:
            self.logger.info(">>> msg: %s", msg)
            if msg.type == aiohttp.WSMsgType.TEXT:
                await ws_to.send_str(msg.data)
            elif msg.type == aiohttp.WSMsgType.BINARY:
                await ws_to.send_bytes(msg.data)
            elif msg.type == aiohttp.WSMsgType.PING:
                await ws_to.ping()
            elif msg.type == aiohttp.WSMsgType.PONG:
                await ws_to.pong()
            elif ws_to.closed:
                await ws_to.close(code=ws_to.close_code, message=msg.extra)
            else:
                raise ValueError("Unexpected message type: %s" % (msg,))

    def subdomain(self, headers):
        """
        Helper method for accessing subdomain protion of Host header. Returns
        None if header not present or subdomain not present.
        """
        host = headers.get("host", False)
        if not host:
            return None
        if not "." in host:
            return None
        # Check for port
        if ":" in host:
            host, _port = host.split(":")
        # Check to see if host is an ip address. If so then then bail
        if all(map(lambda part: part.isdigit(), host.split(".", maxsplit=4))):
            return None
        # Ensure hostname is present
        if not self.hostname in host:
            return None
        # Discard hostname
        host = host[: host.index(self.hostname)]
        # Split on .
        host = list(filter(lambda part: bool(len(part)), host.split(".")))
        return ".".join(host)

    async def handler_proxy(self, req):
        headers = req.headers.copy()
        for remove_header in [
              "X-Real-IP",
              "Forwarded",
              "Via",
              "X-Forwarded-For",
              "X-Forwarded-Proto",
              "X-Forwarded-Host",
              "Host",
        ]:
            if remove_header in headers:
                del headers[remove_header]
        self.logger.debug("headers: %s", headers)

        req_data = await req.read()

        # Pass token through to upstream if not an OIDC token
        # token, token_is_oidc = cgi_helper.get_token()
        token = headers.get("Authorization", "Bearer 0").split()[1]
        if token == "0":
            self.logger.info("Missing required header: Authorization: Bearer {token}: {req.raw_path}")
            return web.Response(status=HTTPStatus.UNAUTHORIZED, message="Missing required header: Authorization: Bearer {token}")
        token_is_oidc = bool(token.count(".") == 2)
        if token_is_oidc:
            # RBAC
            http_method_mapping = {
                "GET": "read",
                "HEAD": "read",
                "OPTIONS": "read",
                "POST": "create",
                "PUT": "update",
                "PATCH": "update",
                "DELETE": "delete"
            }
            permission = http_method_mapping.get(req.method, None)
            if permission is None:
                self.logger.error(f"Unknown permission for HTTP method {req.method}")
                return web.Response(status=HTTPStatus.NOT_ACCEPTABLE)

            kwargs = {}
            if req.query:
                kwargs["query_params"] = dict(req.query)

            if req_data:
                try:
                    req_json = json.loads(req_data)
                except:
                    self.logger.error(f"Only JSON allowed")
                    return web.Response(status=HTTPStatus.NOT_ACCEPTABLE)
                kwargs["req_json"] = req_json

            try:
                oidc_token = rbac_helper.raise_if_unauthorized(
                    token,
                    req.path,
                    permission,
                    **kwargs,
                )
            except cgi_helper.UnauthorizedException as e:
                traceback.print_exc(file=sys.stderr)
                return web.json_response({"id": "unauthorized", "message": str(e)}, status=HTTPStatus.UNAUTHORIZED)

            # Session will manage Authorization header
            del headers["Authorization"]

            try:
                upstream_api_url, session = await self.get_upstream(oidc_token)
            except cgi_helper.UnauthorizedException as e:
                traceback.print_exc(file=sys.stderr)
                return web.json_response({"id": "unauthorized", "message": str(e)}, status=HTTPStatus.UNAUTHORIZED)
        else:
            # TODO NOTE XXX Default to plain proxy to default upstream API
            upstream_api_url = UPSTREAM_API_URL
            session = self.session

        path = req.path
        self.logger.debug("upstream_api_url: %r, path: %r", upstream_api_url, path)

        if (
            headers.get("connection", "").lower() == "upgrade"
            and headers.get("upgrade", "").lower() == "websocket"
            and req.method == "GET"
        ):
            # Handle websocket proxy
            try:
                async with aiohttp.ClientSession(
                    cookies=req.cookies
                ) as client_session:
                    async with client_session.ws_connect(
                        upstream_api_url
                    ) as ws_client:
                        ws_server = web.WebSocketResponse()
                        await ws_server.prepare(req)
                        self.loop.create_task(
                            asyncio.wait(
                                [
                                    self.wsforward(ws_server, ws_client),
                                    self.wsforward(ws_client, ws_server),
                                ],
                                return_when=asyncio.FIRST_COMPLETED,
                            )
                        )
                        return ws_server
            except aiohttp.client_exceptions.WSServerHandshakeError:
                return web.Response(status=HTTPStatus.NOT_FOUND)
        else:
            # Handle regular HTTP request proxy
            url = urljoin(upstream_api_url, path)
            if req.query:
                params = urlencode(req.query)
                url += f"?{params}"
            self.logger.debug(
                "proxying %s -> %s", path, url
            )

            async with session.request(
                req.method,
                url,
                headers=headers,
                allow_redirects=False,
                data=req_data,
            ) as res:
                self.logger.debug(
                    "upstream url(%s) status: %d", url, res.status
                )
                body = await res.read()
                if res.headers.get("Transfer-Encoding", "") == "chunked":
                    response = web.StreamResponse(
                        status=res.status,
                        reason=res.reason,
                        headers=res.headers,
                    )
                    await response.prepare(req)
                    await response.write(body)
                    return response
                else:
                    return web.Response(
                        headers=res.headers,
                        status=res.status,
                        reason=res.reason,
                        body=body,
                    )
            return ws_server

    def set_upstream(self, url: str):
        self.upstream_api_url = url

    async def get_upstream(self, oidc_token):
        cache_key = (oidc_token.aud, oidc_token.sub)
        if cache_key in self.sessions:
            return self.sessions[cache_key]
        if oidc_token.aud.startswith("api://DigitalOcean?"):
            # Use team token for upstream API calls
            team_token = oauth_helper.retrieve_oauth_token(oidc_token.actx)
            session = await self.astack.enter_async_context(
                aiohttp.ClientSession(
                    auto_decompress=False,
                    headers={
                        "Authorization": f"Bearer {team_token}"
                    },
                ),
            )
            self.sessions[cache_key] = (UPSTREAM_API_URL, session)
        elif oidc_token.aud.startswith("api://ATProto?"):
            # TODO Cleaner way for misc APIs
            # user_did = "did:plc:3wh3syflsnsokc7xjdj7xilu"
            user_did = oidc_token.actx
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
                            "PUBLIC_URL": THIS_ENDPOINT,
                            "DB_PATH": os.environ.get(
                                "STATUSPHERE_DB_PATH",
                                "atproto.db"
                            ),
                        },
                    },
                    cwd=os.environ.get(
                        "STATUSPHERE_DIR",
                        str(pathlib.Path(__file__).parents[3].joinpath("statusphere-example-app").resolve()),
                    ),
                ).decode()
            )
            session = await self.astack.enter_async_context(
                DPoPClientSession(
                    key=jwk.JWK.from_json(json.dumps(oauth_session.jwk)),
                    alg="ES256K",
                    headers={
                        "Authorization": f"DPoP {oauth_session.access_token}",
                    }
                ),
            )
            self.sessions[cache_key] = (oauth_session.aud, session)

            """
            ascii_string = pathlib.Path(__file__).read_text()
            # ascii_string = base64.b85encode(lzma.compress(ascii_string.encode('ascii'))).decode('ascii')

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
            async with DPoPClientSession(key=key, alg="ES256K") as session:
                print("\nMaking initial request that will trigger a nonce challenge...")
                headers = {
                    "Authorization": f"DPoP {oauth_session.access_token}",
                    "Content-Type": "application/json",
                }
                url = f"{oauth_session.aud}xrpc/com.atproto.repo.createRecord"
            """

        else:
            raise cgi_helper.UnauthorizedException(f"Invalid audience. No known upstream API.")
        return self.sessions[cache_key]

    async def __aenter__(self) -> "ReverseProxyHandlerContext":
        self.astack = await contextlib.AsyncExitStack().__aenter__()
        self.session = await self.astack.enter_async_context(
            aiohttp.ClientSession(
                auto_decompress=False,
            ),
        )
        self.sessions = {}
        self.app = web.Application()
        self.app.router.add_route("*", "/{path:.*}", self.handler_proxy)
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.loop = asyncio.get_event_loop()
        if self.unix_socket_path is not None:
            self.site = web.UnixSite(self.runner, self.unix_socket_path)
        else:
            self.site = web.TCPSite(self.runner, self.address, self.port)
        await self.site.start()
        if self.unix_socket_path is None:
            self.address, self.port = self.site._server.sockets[0].getsockname()
            self.logger.info(f"started reverse proxy on {self.address}:{self.port}")
        else:
            self.logger.info(f"started reverse proxy on {self.unix_socket_path}")
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.site.stop()
        await self.runner.cleanup()
        await self.astack.__aexit__(exc_type, exc_value, traceback)


class ReverseProxyHandler(object):
    def __init__(self) -> None:
        self.logger = logging.getLogger(__package__).getChild(self.__class__.__qualname__)

    def __call__(
        self, hostname=None, address="127.0.0.1", port=0, unix_socket_path=None,
    ) -> "ReverseProxyHandlerContext":
        return ReverseProxyHandlerContext(
            self, hostname=hostname, address=address, port=port, unix_socket_path=unix_socket_path,
        )


@asynccontextmanager
async def rproxy(self, upstream_path, subdomain, path):
    rproxyh = ReverseProxyHandler()
    async with rproxyh("localhost") as ctx:
        ctx.set_upstream(
            "http://%s:%d%s"
            % (self.server.host, self.server.port, upstream_path),
            subdomain="test",
            path="/route/this",
        )
        yield ctx


class TestReverseProxyHandler(AioHTTPTestCase):

    TEST_ADDRESS = "localhost"
    PROXY_SUBDOMAIN = "test"
    PROXY_PATH = "/route/this"
    UPSTREAM_PATH = "/to/here"

    def fake_socket_getaddrinfo(
        host, port, family=0, type=0, proto=0, flags=0
    ):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))
        ]

    @classmethod
    def setUpClass(cls):
        cls.exit_stack = ExitStack()
        cls.exit_stack.__enter__()
        cls.exit_stack.enter_context(
            patch("socket.getaddrinfo", new=cls.fake_socket_getaddrinfo)
        )

    @classmethod
    def tearDownClass(cls):
        cls.exit_stack.__exit__(None, None, None)

    async def handler(self, request):
        headers = request.headers
        if (
            headers.get("connection", "").lower() == "upgrade"
            and headers.get("upgrade", "").lower() == "websocket"
            and request.method == "GET"
        ):
            ws = web.WebSocketResponse()
            await ws.prepare(request)

            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    await ws.send_str(msg.data)
                elif msg.type == aiohttp.WSMsgType.BINARY:
                    await ws.send_bytes(msg.data)
                elif msg.type == aiohttp.WSMsgType.PING:
                    await ws.ping()
                elif msg.type == aiohttp.WSMsgType.PONG:
                    await ws.pong()
                elif ws.closed:
                    await ws.close(code=ws.close_code, message=msg.extra)

            return ws
        else:
            return web.Response(text=request.path)

    async def get_application(self):
        app = web.Application()
        app.router.add_get(self.UPSTREAM_PATH + "{path:.*}", self.handler)
        return app

    async def test_not_found(self):
        async with rproxy(
            self,
            self.UPSTREAM_PATH,
            subdomain=self.PROXY_SUBDOMAIN,
            path=self.PROXY_PATH,
        ) as rctx, aiohttp.ClientSession() as session:
            url = "http://%s.%s:%d%s" % (
                self.PROXY_SUBDOMAIN + ".not.found",
                self.TEST_ADDRESS,
                rctx.port,
                self.PROXY_PATH,
            )
            LOGGER.debug("rproxy url: %s", url)
            async with session.get(url) as resp:
                self.assertEqual(resp.status, HTTPStatus.NOT_FOUND)

    async def test_path(self):
        async with rproxy(
            self,
            self.UPSTREAM_PATH,
            subdomain=self.PROXY_SUBDOMAIN,
            path=self.PROXY_PATH,
        ) as rctx, aiohttp.ClientSession() as session:
            url = "http://%s.%s:%d%s" % (
                self.PROXY_SUBDOMAIN,
                self.TEST_ADDRESS,
                rctx.port,
                self.PROXY_PATH,
            )
            LOGGER.debug("rproxy url: %s", url)
            async with session.get(url) as resp:
                self.assertEqual(resp.status, HTTPStatus.OK)
                text = await resp.text()
                self.assertEqual(self.UPSTREAM_PATH, text)

    async def test_path_joined(self):
        async with rproxy(
            self,
            self.UPSTREAM_PATH,
            subdomain=self.PROXY_SUBDOMAIN,
            path=self.PROXY_PATH,
        ) as rctx, aiohttp.ClientSession() as session:
            url = "http://%s.%s:%d%s" % (
                self.PROXY_SUBDOMAIN,
                self.TEST_ADDRESS,
                rctx.port,
                self.PROXY_PATH + "/test/joined",
            )
            LOGGER.debug("rproxy url: %s", url)
            async with session.get(url) as resp:
                self.assertEqual(resp.status, HTTPStatus.OK)
                text = await resp.text()
                self.assertEqual(self.UPSTREAM_PATH + "/test/joined", text)

    async def test_websocket(self):
        async with rproxy(
            self,
            self.UPSTREAM_PATH,
            subdomain=self.PROXY_SUBDOMAIN,
            path=self.PROXY_PATH,
        ) as rctx, aiohttp.ClientSession() as session:
            url = "http://%s.%s:%d%s" % (
                self.PROXY_SUBDOMAIN,
                self.TEST_ADDRESS,
                rctx.port,
                self.PROXY_PATH,
            )
            LOGGER.debug("rproxy url: %s", url)
            async with aiohttp.ClientSession() as client_session:
                async with client_session.ws_connect(url) as ws:
                    await ws.send_str(self.UPSTREAM_PATH + "/test/joined")
                    async for msg in ws:
                        text = msg.data
                        self.assertEqual(
                            self.UPSTREAM_PATH + "/test/joined", text
                        )
                        await ws.close()


async def main():
    try:
        rproxyh = ReverseProxyHandler()
        async with rproxyh(
            hostname=THIS_ENDPOINT.split("//")[1],
            address="0.0.0.0",
            port=int(os.getenv("PORT", "8080")),
            unix_socket_path=os.getenv("UNIX_SOCKET_PATH", None),
        ) as _ctx:
            while True:
                await asyncio.sleep(100)
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(main())

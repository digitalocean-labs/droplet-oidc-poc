#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# ///

import argparse
import http.client
import json
import socketserver
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def _ensure_non_empty_content(content):
    if isinstance(content, str):
        return ("done", True) if content.strip() == "" else (content, False)

    if isinstance(content, list):
        changed = False
        out = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text")
                if not isinstance(text, str) or text.strip() == "":
                    copied = dict(block)
                    copied["text"] = "done"
                    out.append(copied)
                    changed = True
                    continue
            out.append(block)
        return (out, changed)

    return (content, False)


def sanitize_chat_completions_body(raw_body: bytes):
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception:
        return raw_body, False

    messages = payload.get("messages")
    if not isinstance(messages, list):
        return raw_body, False

    changed = False
    for idx, msg in enumerate(messages):
        if not isinstance(msg, dict):
            continue
        if "content" not in msg:
            continue
        sanitized, c = _ensure_non_empty_content(msg["content"])
        if c:
            updated = dict(msg)
            updated["content"] = sanitized
            messages[idx] = updated
            changed = True

    if not changed:
        return raw_body, False

    payload["messages"] = messages
    return json.dumps(payload, separators=(",", ":")).encode("utf-8"), True


class ThreadingHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_handler(upstream_base: str):
    upstream = urlsplit(upstream_base)
    if upstream.scheme != "http":
        raise ValueError("only http upstream is supported")

    class ProxyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _forward(self):
            body = b""
            if self.command in {"POST", "PUT", "PATCH"}:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                if self.path == "/v1/chat/completions":
                    body, _ = sanitize_chat_completions_body(body)

            conn = http.client.HTTPConnection(upstream.hostname, upstream.port or 80, timeout=90)
            try:
                headers = {}
                for k, v in self.headers.items():
                    lk = k.lower()
                    if lk in HOP_BY_HOP_HEADERS or lk == "host":
                        continue
                    headers[k] = v
                headers["Host"] = upstream.netloc
                if body:
                    headers["Content-Length"] = str(len(body))

                path = self.path
                conn.request(self.command, path, body=body if body else None, headers=headers)
                resp = conn.getresponse()

                is_chunked = resp.headers.get("Transfer-Encoding", "").lower() == "chunked"

                self.send_response(resp.status, resp.reason)
                for k, v in resp.getheaders():
                    if k.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    self.send_header(k, v)
                if is_chunked:
                    self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()

                if is_chunked:
                    while True:
                        chunk = resp.read(4096)
                        if not chunk:
                            break
                        self.wfile.write(b"%x\r\n%b\r\n" % (len(chunk), chunk))
                        self.wfile.flush()
                    self.wfile.write(b"0\r\n\r\n")
                    self.wfile.flush()
                else:
                    resp_body = resp.read()
                    if resp_body:
                        self.wfile.write(resp_body)
            finally:
                conn.close()

        def do_GET(self):
            self._forward()

        def do_POST(self):
            self._forward()

        def do_PUT(self):
            self._forward()

        def do_PATCH(self):
            self._forward()

        def do_DELETE(self):
            self._forward()

        def log_message(self, fmt, *args):
            return

    return ProxyHandler


def main():
    ap = argparse.ArgumentParser(description="Sanitize and proxy chat completion traffic")
    ap.add_argument("--listen", default="127.0.0.1:4001")
    ap.add_argument("--upstream", default="http://127.0.0.1:4000")
    args = ap.parse_args()

    host, port_s = args.listen.rsplit(":", 1)
    port = int(port_s)
    handler = make_handler(args.upstream)
    server = ThreadingHTTPServer((host, port), handler)
    print(f"sanitize proxy listening on {args.listen} -> {args.upstream}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

"""A plain-HTTP forward proxy (no HTTPS on purpose: the demo needs to READ the request_id header).

For every connection it forwards, it records: direction, destination, bytes sent, the
request_id header if it can see one, and the result. It posts that record to its own
Network witness. If no valid request_id is visible, the record's request_id is empty.

"Bytes" means HTTP body bytes actually forwarded to the destination.
"""
import http.client
import http.server
import json
import re
import threading
from urllib.parse import urlsplit

REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")
HOP_BY_HOP = {"connection", "proxy-connection", "keep-alive", "te", "trailer", "transfer-encoding",
              "upgrade", "proxy-authorization", "proxy-authenticate"}


class Counters:
    def __init__(self):
        self._lock = threading.Lock()
        self.connections = 0
        self.bytes_forwarded = 0
        self.errors = 0

    def add(self, size, ok):
        with self._lock:
            self.connections += 1
            self.bytes_forwarded += size
            self.errors += 0 if ok else 1

    def snapshot(self):
        with self._lock:
            return {"connections": self.connections, "bytes_forwarded": self.bytes_forwarded, "errors": self.errors}


def make_handler(poster, label, upstream_timeout):
    counters = Counters()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "LogSabhaGateway"

        def log_message(self, fmt, *args):      # keep the console quiet
            pass

        def _reply(self, code, body=b"", headers=()):
            self.send_response(code)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _admin(self):
            if self.path == "/status":
                info = {"service": "gateway", "label": label, **counters.snapshot()}
                self._reply(200, json.dumps(info).encode(), [("Content-Type", "application/json")])
            else:
                self._reply(404, b"this is a proxy: send absolute http:// URLs")

        def _forward(self):
            if self.path.startswith("/"):       # a request to the gateway itself, not to be proxied
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                return self._admin()

            target = urlsplit(self.path)
            if target.scheme != "http" or not target.hostname:
                return self._reply(400, b"only plain http:// URLs are supported")
            if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
                return self._reply(411, b"Content-Length is required")
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""

            host, port = target.hostname, target.port or 80
            dst = "%s:%d" % (host, port)
            raw_id = (self.headers.get("X-Request-ID") or "").strip().lower()
            request_id = raw_id if REQUEST_ID.match(raw_id) else ""     # empty if not visible

            headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}
            headers["Host"] = target.netloc
            path = (target.path or "/") + ("?" + target.query if target.query else "")

            sent, status, data, resp_headers = 0, 502, b"", []
            result = "error:upstream_unreachable"
            conn = http.client.HTTPConnection(host, port, timeout=upstream_timeout)
            try:
                conn.connect()
                conn.request(self.command, path, body=body or None, headers=headers)
                sent = len(body)                                       # the whole body went out
                resp = conn.getresponse()
                data = resp.read()
                status = resp.status
                resp_headers = [(k, v) for k, v in resp.getheaders()
                                if k.lower() not in HOP_BY_HOP and k.lower() != "content-length"]
                result = "ok:%d" % status if status < 400 else "error:http_%d" % status
            except (OSError, http.client.HTTPException):
                if sent:
                    result = "error:no_answer"
            finally:
                conn.close()

            poster.post("connection", request_id, "out", dst, sent, result)
            counters.add(sent, result.startswith("ok"))
            self._reply(status, data, resp_headers)

        def do_CONNECT(self):
            self._reply(405, b"HTTPS tunnelling is not supported in the demo (plain HTTP only)")

        do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = _forward

    return Handler, counters


def make_server(host, port, poster, label="", upstream_timeout=60):
    handler, counters = make_handler(poster, label, upstream_timeout)
    server = http.server.ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    server.counters = counters
    return server

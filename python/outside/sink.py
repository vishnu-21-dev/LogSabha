"""Sink mode: a listening "outside server" that exports are sent to.

It counts the bytes it ACTUALLY receives (it reads the body off the socket and counts what
arrived), per source address, and posts one flow record per request to its own Outside witness.
"Bytes" means HTTP body bytes received.
"""
import http.server
import json
import re
import threading

REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")


class SinkStats:
    def __init__(self):
        self._lock = threading.Lock()
        self.per_source = {}

    def add(self, source, size):
        with self._lock:
            row = self.per_source.setdefault(source, {"requests": 0, "bytes": 0})
            row["requests"] += 1
            row["bytes"] += size

    def snapshot(self):
        with self._lock:
            return {k: dict(v) for k, v in self.per_source.items()}


def make_handler(poster, stats, label):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "LogSabhaOutsideSink"

        def log_message(self, fmt, *args):
            pass

        def _reply(self, code, payload):
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _receive(self):
            if self.command == "GET" and self.path == "/__stats":      # our own counters, nobody else's
                return self._reply(200, {"service": "outside_sink", "label": label, "per_source": stats.snapshot()})
            if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
                return self._reply(411, {"error": "Content-Length is required"})
            expected = int(self.headers.get("Content-Length") or 0)
            got = 0
            while got < expected:                      # count what really arrives, not what was announced
                chunk = self.rfile.read(min(65536, expected - got))
                if not chunk:
                    break
                got += len(chunk)

            source = self.client_address[0]
            destination = self.headers.get("Host") or "%s:%d" % self.server.server_address[:2]
            raw_id = (self.headers.get("X-Request-ID") or "").strip().lower()
            request_id = raw_id if REQUEST_ID.match(raw_id) else ""   # only if this request really carried one
            outcome = "ok" if got == expected else "partial"

            poster.post("flow", request_id, "in", destination, got, "%s;src=%s" % (outcome, source))
            stats.add(source, got)
            self._reply(200, {"received": got})

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _receive

    return Handler


def make_server(host, port, poster, label=""):
    stats = SinkStats()
    server = http.server.ThreadingHTTPServer((host, port), make_handler(poster, stats, label))
    server.daemon_threads = True
    server.stats = stats
    return server

#!/usr/bin/env python3
"""Mock PHP target used by the scanner verdict smoke tests.

Usage: python3 tests/mock_server.py <port> <mode> [php_version]

Modes:
  clean -> control and probe requests are handled normally
  vuln  -> probes answer with the in-band PHP memory-exhaustion fatal error
  fpm   -> probes kill the worker, so the fronting server answers 502

The advertised X-Powered-By version defaults to 8.4.27 (patched).
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
MODE = sys.argv[2] if len(sys.argv) > 2 else "clean"
PHP_VERSION = sys.argv[3] if len(sys.argv) > 3 else "8.4.27"

FATAL = (
    b"<br />\n<b>Fatal error</b>:  Allowed memory size of 134217728 bytes "
    b"exhausted (tried to allocate 20480 bytes) in <b>Unknown</b> on line "
    b"<b>0</b><br />\n"
)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self._respond(200, b"ok")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            remaining -= len(chunk)

        probe = length > 1000
        if probe and MODE == "vuln":
            return self._respond(500, FATAL)
        if probe and MODE == "fpm":
            return self._respond(502, b"Bad Gateway")
        self._respond(200, b"<html>hello</html>")

    def _respond(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "PHP/" + PHP_VERSION)
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()

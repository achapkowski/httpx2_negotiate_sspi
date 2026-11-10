"""Minimal SPNEGO/Kerberos HTTP server for Linux integration tests.

Usage::

    python tests/integration_server.py <port> <mode>

Modes:
    good      Authenticate fully and send the final token in WWW-Authenticate.
    no-token  Authenticate successfully but omit the final token.
    bad-token Send 200 with an invalid (non-base64) WWW-Authenticate token.

The server reads the keytab path from the KRB5_KTNAME environment variable.
Set KRB_TEST_URL=http://localhost:<port>/ before running the client tests.
"""
from __future__ import annotations

import base64
import http.server
import os
import sys

import spnego
import spnego.exceptions

_MODE = "good"
_SCHEME = "Negotiate"


class NegotiateHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence access log

    def _send_401(self, token: bytes | None = None):
        self.send_response(401)
        if token is not None:
            value = "{} {}".format(
                _SCHEME, base64.b64encode(token).decode("ascii")
            )
        else:
            value = _SCHEME
        self.send_header("WWW-Authenticate", value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send_200(self, token: bytes | None = None, bad: bool = False):
        self.send_response(200)
        if bad:
            self.send_header("WWW-Authenticate", "{} !!!invalid!!!".format(_SCHEME))
        elif token is not None:
            value = "{} {}".format(
                _SCHEME, base64.b64encode(token).decode("ascii")
            )
            self.send_header("WWW-Authenticate", value)
        body = b"OK"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.lower().startswith(_SCHEME.lower() + " "):
            self._send_401()
            return

        in_token = base64.b64decode(auth_header[len(_SCHEME) + 1:].strip())

        try:
            ctx = spnego.server(
                service="http",
                hostname="localhost",
                protocol="negotiate",
                options=spnego.NegotiateOptions.use_gssapi,
            )
            out_token = ctx.step(in_token)
            while not ctx.complete and out_token is not None:
                # Send intermediate token and wait for next client token
                self._send_401(out_token)
                return
        except spnego.exceptions.SpnegoError:
            self._send_401()
            return

        # Authentication complete
        if _MODE == "good":
            self._send_200(out_token)
        elif _MODE == "no-token":
            self._send_200(token=None)
        elif _MODE == "bad-token":
            self._send_200(bad=True)
        else:
            self._send_200(token=None)


def main():
    global _MODE
    if len(sys.argv) < 3:
        print("Usage: integration_server.py <port> <mode>", file=sys.stderr)
        sys.exit(1)
    port = int(sys.argv[1])
    _MODE = sys.argv[2]
    server = http.server.HTTPServer(("127.0.0.1", port), NegotiateHandler)
    print("Listening on port {}  mode={}".format(port, _MODE), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

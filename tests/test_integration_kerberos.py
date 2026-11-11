"""Integration tests against a real Kerberos KDC on a GitHub Ubuntu runner.

Skipped unless KRB_TEST_URL is set (the CI workflow injects it after kinit).
The server is started by the CI workflow using tests/integration_server.py.
"""
from __future__ import annotations

import os
import unittest

import httpx2

from httpx2_negotiate_sspi import HttpNegotiateAuth
from httpx2_negotiate_sspi.api import MutualAuthenticationError

_BASE_URL = os.environ.get("KRB_TEST_URL", "").rstrip("/")


def _url(mode: str) -> str:
    """Return the test server URL for a given mode path."""
    # The integration_server listens on a single port with a single mode;
    # the CI starts three separate server processes on different ports.
    port_map = {
        "good": os.environ.get("KRB_PORT_GOOD", "8080"),
        "no-token": os.environ.get("KRB_PORT_NO_TOKEN", "8081"),
        "bad-token": os.environ.get("KRB_PORT_BAD_TOKEN", "8082"),
    }
    base = _BASE_URL.rsplit(":", 1)[0]  # strip port
    return "{}:{}/".format(base, port_map[mode])


@unittest.skipUnless(
    _BASE_URL, "KRB_TEST_URL not set — skipping Kerberos integration tests"
)
class KerberosIntegrationTests(unittest.TestCase):
    """Real Kerberos tests against the integration server.

    The GitHub runner is not domain-joined; this tests Kerberos ticket-cache
    (kinit) authentication against a locally-configured KDC.
    """

    def test_1_good_mode_returns_200(self):
        """Full mutual authentication, server sends final token → 200."""
        auth = HttpNegotiateAuth()
        with httpx2.Client(auth=auth) as client:
            response = client.get(_url("good"))
        self.assertEqual(response.status_code, 200)

    def test_2_no_token_mode_raises(self):
        """Server omits final token (mutual_authentication=True) → MutualAuthenticationError."""
        auth = HttpNegotiateAuth()
        with self.assertRaises(MutualAuthenticationError):
            with httpx2.Client(auth=auth) as client:
                client.get(_url("no-token"))

    def test_3_bad_token_mode_raises(self):
        """Server sends invalid final token → MutualAuthenticationError."""
        auth = HttpNegotiateAuth()
        with self.assertRaises(MutualAuthenticationError):
            with httpx2.Client(auth=auth) as client:
                client.get(_url("bad-token"))

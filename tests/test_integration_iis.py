"""Integration tests against a real IIS server on GitHub-hosted Windows runners.

Skipped unless IIS_TEST_URL is set in the environment (the CI workflow injects
it). Uses httpx2.Client(verify=False) for self-signed certificates.
"""
from __future__ import annotations

import os
import unittest

import httpx2

from httpx2_negotiate_sspi import HttpNegotiateAuth
from httpx2_negotiate_sspi.api import MutualAuthenticationError

_IIS_URL = os.environ.get("IIS_TEST_URL", "")
_IIS_URL_SHA384 = os.environ.get("IIS_TEST_URL_SHA384", "")
_TEST_USER = os.environ.get("TEST_USER", "")
_TEST_PASSWORD = os.environ.get("TEST_PASSWORD", "")


@unittest.skipUnless(_IIS_URL, "IIS_TEST_URL not set — skipping IIS integration tests")
class IISIntegrationTests(unittest.TestCase):
    """NTLM + channel-binding tests against a real IIS server.

    CI uses a GitHub-hosted Windows runner which is not domain-joined, so
    Kerberos is not available. These tests exercise NTLM and channel binding
    only.
    """

    def _make_auth(self, **kwargs):
        return HttpNegotiateAuth(
            username=_TEST_USER,
            password=_TEST_PASSWORD,
            **kwargs,
        )

    def test_1_ntlm_with_channel_binding_mutual_auth_false(self):
        """Explicit NTLM credentials + channel binding, mutual_auth=False → 200."""
        auth = self._make_auth(mutual_authentication=False)
        with httpx2.Client(auth=auth, verify=False) as client:
            response = client.get(_IIS_URL)
        self.assertEqual(response.status_code, 200)

    def test_2_default_mutual_auth_raises(self):
        """Default settings (mutual_authentication=True) → MutualAuthenticationError.

        NTLM cannot prove the server's identity, so the library correctly
        rejects the response.
        """
        auth = self._make_auth()
        with self.assertRaises(MutualAuthenticationError):
            with httpx2.Client(auth=auth, verify=False) as client:
                client.get(_IIS_URL)

    @unittest.skipUnless(
        _IIS_URL_SHA384,
        "IIS_TEST_URL_SHA384 not set — skipping SHA-384 channel binding test",
    )
    def test_3_sha384_site_mutual_auth_false(self):
        """SHA-384 certificate site with mutual_auth=False → 200.

        Verifies that the channel binding hash selection uses SHA-384 for
        a certificate signed with SHA-384 (RFC 5929 §4.1 fix).
        """
        auth = self._make_auth(mutual_authentication=False)
        with httpx2.Client(auth=auth, verify=False) as client:
            response = client.get(_IIS_URL_SHA384)
        self.assertEqual(response.status_code, 200)

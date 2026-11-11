"""Required test cases for mutual authentication, channel binding, and hostname
canonicalization.

All tests run on Windows and non-Windows platforms. pyspnego is a real
dependency, so there are no stub modules; we mock ``spnego.client`` to return
a controlled fake context.
"""
from __future__ import annotations

import base64
import hashlib
import importlib
import sys
import unittest
from unittest import mock

import httpx2
import spnego
import spnego.channel_bindings
import spnego.exceptions

api = importlib.import_module("httpx2_negotiate_sspi.api")


# ---------------------------------------------------------------------------
# Shared fake context
# ---------------------------------------------------------------------------


class FakeContext:
    """Fake pyspnego client context used in every unit test.

    Behaviour:
    - step(None)       → returns b"initial-token"; complete stays False
    - step(b"good")    → returns None; sets complete=True, context_attr=mutual_auth
    - step(other)      → raises SpnegoError (simulates a bad final token)
    - step(challenge)  → returns b"response-token" for any bytes != b"good"/"bad"
    """

    def __init__(self, **kwargs):
        self.complete = False
        self.context_attr = spnego.ContextReq(0)
        self.calls: list = []
        self.create_kwargs = kwargs

    def step(self, in_token=None):
        self.calls.append(in_token)
        if in_token is None:
            return b"initial-token"
        if in_token == b"good":
            self.complete = True
            self.context_attr = spnego.ContextReq.mutual_auth
            return None
        if in_token == b"bad":
            raise spnego.exceptions.SpnegoError(error_code=9)
        # Multi-leg challenge token (any other bytes): return response token
        return b"response-token"


def _make_fake_client(test_case):
    """Patch spnego.client and return the list of created FakeContext objects."""
    instances: list[FakeContext] = []

    def fake_client(**kwargs):
        ctx = FakeContext(**kwargs)
        instances.append(ctx)
        return ctx

    test_case.contexts = instances
    return mock.patch.object(api.spnego, "client", side_effect=fake_client)


def _make_401(request, scheme="Negotiate"):
    return httpx2.Response(
        401, headers={"WWW-Authenticate": scheme}, request=request
    )


def _make_200(request, final_token=None, scheme="Negotiate"):
    headers = {}
    if final_token is not None:
        b64 = base64.b64encode(final_token).decode("ascii")
        headers["WWW-Authenticate"] = "{} {}".format(scheme, b64)
    return httpx2.Response(200, headers=headers, request=request)


def _run_single_leg(auth, scheme="Negotiate", final_token=None):
    """Drive a single-leg flow (initial 401 → 200) and return the final response."""
    request = httpx2.Request("GET", "https://example.com/")
    flow = auth.auth_flow(request)
    first_request = next(flow)
    retry_request = flow.send(_make_401(first_request, scheme))
    final_response = _make_200(retry_request, final_token, scheme)
    try:
        flow.send(final_response)
    except StopIteration:
        pass
    return final_response


def _run_multi_leg(auth, challenge_bytes=b"challenge", final_token=None,
                   scheme="NTLM"):
    """Drive a two-leg NTLM-like flow and return the final response."""
    request = httpx2.Request("GET", "https://example.com/")
    flow = auth.auth_flow(request)
    first_request = next(flow)
    retry_request = flow.send(_make_401(first_request, scheme))

    challenge_b64 = base64.b64encode(challenge_bytes).decode("ascii")
    second_retry = flow.send(
        httpx2.Response(
            401,
            headers={"WWW-Authenticate": "{} {}".format(scheme, challenge_b64)},
            request=retry_request,
        )
    )
    final_response = _make_200(second_retry, final_token, scheme)
    try:
        flow.send(final_response)
    except StopIteration:
        pass
    return final_response


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------


class MutualAuthSingleLegTests(unittest.TestCase):
    """Tests 1–4: single-leg flow (Kerberos-like)."""

    def setUp(self):
        self.patch = _make_fake_client(self)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()

    def test_1_no_final_token_raises(self):
        """200 with no WWW-Authenticate → MutualAuthenticationError."""
        auth = api.HttpNegotiateAuth(host="server.example.com")
        request = httpx2.Request("GET", "https://example.com/")
        flow = auth.auth_flow(request)
        first = next(flow)
        retry = flow.send(_make_401(first))
        with self.assertRaises(api.MutualAuthenticationError):
            flow.send(_make_200(retry, final_token=None))

    def test_2_bad_final_token_raises(self):
        """200 with an invalid final token → MutualAuthenticationError."""
        auth = api.HttpNegotiateAuth(host="server.example.com")
        request = httpx2.Request("GET", "https://example.com/")
        flow = auth.auth_flow(request)
        first = next(flow)
        retry = flow.send(_make_401(first))
        with self.assertRaises(api.MutualAuthenticationError):
            flow.send(_make_200(retry, final_token=b"bad"))

    def test_3_good_final_token_returns_response(self):
        """200 with a valid final token → response returned (no error)."""
        auth = api.HttpNegotiateAuth(host="server.example.com")
        resp = _run_single_leg(auth, final_token=b"good")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(self.contexts[0].complete)

    def test_4_mutual_auth_false_no_token_ok(self):
        """mutual_authentication=False, no final token → response returned."""
        auth = api.HttpNegotiateAuth(
            host="server.example.com", mutual_authentication=False
        )
        resp = _run_single_leg(auth, final_token=None)
        self.assertEqual(resp.status_code, 200)


class MutualAuthMultiLegTests(unittest.TestCase):
    """Tests 5–6: multi-leg flow (NTLM-like)."""

    def setUp(self):
        self.patch = _make_fake_client(self)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()

    def test_5_ntlm_mutual_auth_raises_before_credentials(self):
        """NTLM advertised + mutual_authentication=True → raises before sending credentials."""
        auth = api.HttpNegotiateAuth(host="server.example.com", mutual_authentication=True)
        request = httpx2.Request("GET", "https://example.com/")
        flow = auth.auth_flow(request)
        first = next(flow)
        with self.assertRaises(api.MutualAuthenticationError) as exc_ctx:
            flow.send(_make_401(first, "NTLM"))
        self.assertIn("ntlm", str(exc_ctx.exception).lower())
        # spnego.client must not have been called — no credentials were sent
        self.assertEqual(self.contexts, [])

    def test_5_multi_leg_negotiate_no_final_token_raises(self):
        """Multi-leg Negotiate exchange ending with no final token → MutualAuthenticationError."""
        auth = api.HttpNegotiateAuth(host="server.example.com", mutual_authentication=True)
        request = httpx2.Request("GET", "https://example.com/")
        flow = auth.auth_flow(request)
        first = next(flow)
        retry = flow.send(_make_401(first, "Negotiate"))
        challenge_b64 = base64.b64encode(b"challenge").decode("ascii")
        second_retry = flow.send(
            httpx2.Response(
                401,
                headers={"WWW-Authenticate": "Negotiate {}".format(challenge_b64)},
                request=retry,
            )
        )
        with self.assertRaises(api.MutualAuthenticationError):
            flow.send(_make_200(second_retry, final_token=None, scheme="Negotiate"))

    def test_5b_multi_leg_success_mutual_auth_false(self):
        """Multi-leg with mutual_authentication=False succeeds without final token."""
        auth = api.HttpNegotiateAuth(host="server.example.com", mutual_authentication=False)
        resp = _run_multi_leg(auth, challenge_bytes=b"challenge", final_token=None)
        self.assertEqual(resp.status_code, 200)

    def test_5c_out_token_none_breaks_loop(self):
        """ctx.step() returning None during multi-leg exits the handshake loop."""

        class StepNoneContext:
            complete = False
            context_attr = spnego.ContextReq(0)

            def __init__(self, **kwargs):
                pass

            def step(self, in_token=None):
                if in_token is None:
                    return b"initial-token"
                return None

        with mock.patch.object(api.spnego, "client",
                               side_effect=lambda **kw: StepNoneContext()):
            auth = api.HttpNegotiateAuth(host="server.example.com",
                                        mutual_authentication=False)
            request = httpx2.Request("GET", "https://example.com/")
            flow = auth.auth_flow(request)
            first = next(flow)
            retry = flow.send(_make_401(first, "NTLM"))
            challenge_b64 = base64.b64encode(b"challenge").decode("ascii")
            with self.assertRaises(StopIteration):
                flow.send(httpx2.Response(
                    401,
                    headers={"WWW-Authenticate": "NTLM {}".format(challenge_b64)},
                    request=retry,
                ))

    def test_6_negotiate_complete_no_mutual_auth_flag_raises(self):
        """ctx.complete=True but mutual_auth flag not set → MutualAuthenticationError.

        A Negotiate context that marks itself complete without the mutual_auth
        attribute must still fail the mutual-auth check.
        """
        class NoMutualAuthContext:
            def __init__(self, **kwargs):
                self.complete = False
                self.context_attr = spnego.ContextReq(0)

            def step(self, in_token=None):
                if in_token is None:
                    return b"initial-token"
                self.complete = True
                return b"response-token"

        auth = api.HttpNegotiateAuth(host="server.example.com")

        with mock.patch.object(api.spnego, "client",
                               side_effect=lambda **kw: NoMutualAuthContext()):
            request = httpx2.Request("GET", "https://example.com/")
            flow = auth.auth_flow(request)
            first = next(flow)
            retry = flow.send(_make_401(first, "Negotiate"))
            challenge_b64 = base64.b64encode(b"challenge").decode("ascii")
            second_retry = flow.send(
                httpx2.Response(
                    401,
                    headers={"WWW-Authenticate": "Negotiate {}".format(challenge_b64)},
                    request=retry,
                )
            )
            with self.assertRaises(api.MutualAuthenticationError):
                flow.send(_make_200(second_retry, final_token=None, scheme="Negotiate"))


class CredentialAndHostnameTests(unittest.TestCase):
    """Tests 7–9: credential passing and hostname canonicalization."""

    def setUp(self):
        self.patch = _make_fake_client(self)
        self.patch.start()
        self.getaddrinfo_patch = mock.patch.object(
            api.socket,
            "getaddrinfo",
            return_value=[(None, None, None, "canonical.example.com")],
        )
        self.getaddrinfo_patch.start()

    def tearDown(self):
        self.getaddrinfo_patch.stop()
        self.patch.stop()

    def _run_to_retry(self, auth, scheme="Negotiate"):
        request = httpx2.Request("GET", "https://example.com/")
        flow = auth.auth_flow(request)
        first = next(flow)
        retry = flow.send(_make_401(first, scheme))
        # Stop flow cleanly
        try:
            flow.send(_make_200(retry, final_token=b"good"))
        except StopIteration:
            pass
        return self.contexts[-1]

    def test_7_no_credentials_uses_sso_windows(self):
        """No credentials on Windows → use_sspi option passed."""
        with mock.patch.object(api.sys, "platform", "win32"):
            self._run_to_retry(api.HttpNegotiateAuth())
        ctx = self.contexts[-1]
        self.assertIsNone(ctx.create_kwargs["username"])
        self.assertIsNone(ctx.create_kwargs["password"])
        self.assertEqual(
            ctx.create_kwargs["options"], spnego.NegotiateOptions.use_sspi
        )

    def test_7_no_credentials_uses_sso_linux(self):
        """No credentials on Linux → use_gssapi option passed."""
        with mock.patch.object(api.sys, "platform", "linux"):
            self._run_to_retry(api.HttpNegotiateAuth())
        ctx = self.contexts[-1]
        self.assertIsNone(ctx.create_kwargs["username"])
        self.assertIsNone(ctx.create_kwargs["password"])
        self.assertEqual(
            ctx.create_kwargs["options"], spnego.NegotiateOptions.use_gssapi
        )

    def test_8_explicit_credentials_with_domain(self):
        """username + domain → 'DOMAIN\\user' sent to spnego.client."""
        auth = api.HttpNegotiateAuth(
            username="alice", password="secret", domain="CORP"
        )
        self._run_to_retry(auth)
        ctx = self.contexts[-1]
        self.assertEqual(ctx.create_kwargs["username"], "CORP\\alice")
        self.assertEqual(ctx.create_kwargs["password"], "secret")
        self.assertEqual(ctx.create_kwargs["options"], spnego.NegotiateOptions(0))

    def test_8_explicit_credentials_with_domain_dot_not_prepended(self):
        """domain='.' → username not prefixed."""
        auth = api.HttpNegotiateAuth(username="alice", password="secret", domain=".")
        self._run_to_retry(auth)
        ctx = self.contexts[-1]
        self.assertEqual(ctx.create_kwargs["username"], "alice")

    def test_8_username_with_backslash_not_modified(self):
        """username already has domain prefix → not double-prefixed."""
        auth = api.HttpNegotiateAuth(
            username="CORP\\alice", password="secret", domain="CORP"
        )
        self._run_to_retry(auth)
        ctx = self.contexts[-1]
        self.assertEqual(ctx.create_kwargs["username"], "CORP\\alice")

    def test_9_canonicalize_false_no_getaddrinfo(self):
        """canonicalize_hostname=False → socket.getaddrinfo not called."""
        self._run_to_retry(api.HttpNegotiateAuth(canonicalize_hostname=False))
        api.socket.getaddrinfo.assert_not_called()

    def test_9_canonicalize_true_calls_getaddrinfo(self):
        """canonicalize_hostname=True → socket.getaddrinfo called."""
        self._run_to_retry(
            api.HttpNegotiateAuth(canonicalize_hostname=True)
        )
        api.socket.getaddrinfo.assert_called_once()
        ctx = self.contexts[-1]
        self.assertEqual(ctx.create_kwargs["hostname"], "canonical.example.com")

    def test_9_explicit_host_overrides_canonicalize(self):
        """Explicit host= takes priority; getaddrinfo never called."""
        auth = api.HttpNegotiateAuth(host="fixed.example.com", canonicalize_hostname=True)
        self._run_to_retry(auth)
        api.socket.getaddrinfo.assert_not_called()
        ctx = self.contexts[-1]
        self.assertEqual(ctx.create_kwargs["hostname"], "fixed.example.com")


class ChannelBindingHashTests(unittest.TestCase):
    """Test 10: channel binding uses the correct hash per RFC 5929 §4.1."""

    def _assert_cert_hash(self, der: bytes, expected_hashlib_name: str):
        actual = api._cert_hash_name(der)
        self.assertEqual(actual, expected_hashlib_name)

    def _make_cert_der(self, hash_algo_oid: str) -> bytes:
        """Build a minimal DER certificate with the given signatureAlgorithm OID."""
        def encode_oid(dotted: str) -> bytes:
            parts = list(map(int, dotted.split(".")))
            body = bytes([parts[0] * 40 + parts[1]])
            for n in parts[2:]:
                if n == 0:
                    body += b"\x00"
                    continue
                buf = []
                buf.append(n & 0x7F)
                n >>= 7
                while n:
                    buf.append(0x80 | (n & 0x7F))
                    n >>= 7
                body += bytes(reversed(buf))
            return b"\x06" + bytes([len(body)]) + body

        def der_seq(content: bytes) -> bytes:
            return b"\x30" + bytes([len(content)]) + content

        oid_der = encode_oid(hash_algo_oid)
        alg_id = der_seq(oid_der)             # signatureAlgorithm
        tbs = der_seq(b"\x05\x00")            # trivial tbsCertificate placeholder
        # outer Certificate: tbsCertificate + signatureAlgorithm + stub signature
        inner = tbs + alg_id + b"\x03\x01\x00"
        return der_seq(inner)

    def test_sha256_cert_uses_sha256(self):
        der = self._make_cert_der("1.2.840.113549.1.1.11")  # sha256WithRSAEncryption
        self._assert_cert_hash(der, "sha256")

    def test_sha384_cert_uses_sha384(self):
        der = self._make_cert_der("1.2.840.113549.1.1.12")  # sha384WithRSAEncryption
        self._assert_cert_hash(der, "sha384")

    def test_sha512_cert_uses_sha512(self):
        der = self._make_cert_der("1.2.840.113549.1.1.13")  # sha512WithRSAEncryption
        self._assert_cert_hash(der, "sha512")

    def test_sha1_cert_promoted_to_sha256(self):
        der = self._make_cert_der("1.2.840.113549.1.1.5")   # sha1WithRSAEncryption
        self._assert_cert_hash(der, "sha256")

    def test_md5_cert_promoted_to_sha256(self):
        der = self._make_cert_der("1.2.840.113549.1.1.4")   # md5WithRSAEncryption
        self._assert_cert_hash(der, "sha256")

    def test_unknown_oid_falls_back_to_sha256(self):
        der = self._make_cert_der("1.3.101.112")  # Ed25519 (no hash component)
        self._assert_cert_hash(der, "sha256")

    def test_unparseable_der_falls_back_to_sha256(self):
        self._assert_cert_hash(b"not-a-cert", "sha256")

    def test_oid_with_zero_arc_encoded_correctly(self):
        """OID with a zero arc hits the n==0 branch in _make_cert_der's encode_oid."""
        der = self._make_cert_der("1.2.0")
        self.assertEqual(api._cert_hash_name(der), "sha256")

    def test_channel_bindings_carries_correct_digest(self):
        """The GssChannelBindings application_data uses the right hash."""
        patch = _make_fake_client(self)
        patch.start()
        self.addCleanup(patch.stop)

        # Build a minimal SHA-384 cert
        der = self._make_cert_der("1.2.840.113549.1.1.12")

        class FakeSSLObj:
            def getpeercert(self, binary_form=False):
                return der

        class FakeStream:
            def get_extra_info(self, name):
                return FakeSSLObj() if name == "ssl_object" else None

        auth = api.HttpNegotiateAuth(mutual_authentication=False)
        request = httpx2.Request("GET", "https://example.com/")
        flow = auth.auth_flow(request)
        first = next(flow)
        flow.send(
            httpx2.Response(
                401,
                headers={"WWW-Authenticate": "Negotiate"},
                request=first,
                extensions={"network_stream": FakeStream()},
            )
        )

        cb = self.contexts[0].create_kwargs.get("channel_bindings")
        self.assertIsNotNone(cb)
        expected = b"tls-server-end-point:" + hashlib.sha384(der).digest()
        self.assertEqual(cb.application_data, expected)


class RoundLimitTest(unittest.TestCase):
    """Test 11: handshake round limit raises HTTPError."""

    def test_round_limit_raises(self):
        """Loop that always returns 401 must hit the round limit."""
        instances: list = []

        class NeverDoneContext:
            complete = False
            context_attr = spnego.ContextReq(0)

            def __init__(self, **kwargs):
                instances.append(self)

            def step(self, in_token=None):
                return b"token"

        with mock.patch.object(api.spnego, "client",
                               side_effect=lambda **kw: NeverDoneContext(**kw)):
            auth = api.HttpNegotiateAuth(host="server.example.com",
                                         mutual_authentication=False)
            request = httpx2.Request("GET", "https://example.com/")
            flow = auth.auth_flow(request)
            first = next(flow)
            current_req = flow.send(_make_401(first, "NTLM"))
            with self.assertRaises(httpx2.HTTPError) as ctx:
                for _ in range(api._MAX_HANDSHAKE_ROUNDS + 2):
                    challenge_b64 = base64.b64encode(b"challenge").decode("ascii")
                    current_req = flow.send(
                        httpx2.Response(
                            401,
                            headers={"WWW-Authenticate": "NTLM {}".format(challenge_b64)},
                            request=current_req,
                        )
                    )
            self.assertIn("rounds", str(ctx.exception).lower())


class AsyncMutualAuthTests(unittest.IsolatedAsyncioTestCase):
    """Test 12: async client reproduces cases 1, 3 and 4."""

    def setUp(self):
        self.patch = _make_fake_client(self)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()

    async def _run_async_single_leg(self, auth, final_token=None, scheme="Negotiate"):
        request = httpx2.Request("GET", "https://example.com/")
        flow = auth.async_auth_flow(request)
        first = await flow.__anext__()
        retry = await flow.asend(_make_401(first, scheme))
        return flow, retry, _make_200(retry, final_token, scheme)

    async def test_async_1_no_final_token_raises(self):
        auth = api.HttpNegotiateAuth(host="server.example.com")
        flow, retry, final_resp = await self._run_async_single_leg(auth)
        with self.assertRaises(api.MutualAuthenticationError):
            await flow.asend(final_resp)

    async def test_async_3_good_final_token_returns(self):
        auth = api.HttpNegotiateAuth(host="server.example.com")
        flow, retry, final_resp = await self._run_async_single_leg(
            auth, final_token=b"good"
        )
        with self.assertRaises(StopAsyncIteration):
            await flow.asend(final_resp)
        self.assertTrue(self.contexts[0].complete)

    async def test_async_4_no_mutual_auth_no_token_ok(self):
        auth = api.HttpNegotiateAuth(
            host="server.example.com", mutual_authentication=False
        )
        flow, retry, final_resp = await self._run_async_single_leg(auth)
        with self.assertRaises(StopAsyncIteration):
            await flow.asend(final_resp)


class MissingBackendTest(unittest.TestCase):
    """Test 13: missing SSPI/GSSAPI backend gives a clear error message."""

    def test_missing_backend_raises_with_hint(self):
        def unavailable_client(**kwargs):
            raise spnego.exceptions.SpnegoError(error_code=9)

        auth = api.HttpNegotiateAuth(host="server.example.com")
        request = httpx2.Request("GET", "https://example.com/")
        flow = auth.auth_flow(request)
        first = next(flow)

        with mock.patch.object(api.spnego, "client", side_effect=unavailable_client):
            with self.assertRaises(httpx2.HTTPError) as ctx:
                flow.send(_make_401(first))

        msg = str(ctx.exception).lower()
        self.assertIn("spnego", msg)

    def test_missing_backend_non_windows_hint(self):
        """On non-Windows, error hint mentions kinit."""
        def unavailable_client(**kwargs):
            raise spnego.exceptions.SpnegoError(error_code=9)

        auth = api.HttpNegotiateAuth(host="server.example.com")
        request = httpx2.Request("GET", "https://example.com/")
        flow = auth.auth_flow(request)
        first = next(flow)

        with mock.patch.object(api.spnego, "client", side_effect=unavailable_client), \
             mock.patch.object(api.sys, "platform", "linux"):
            with self.assertRaises(httpx2.HTTPError) as ctx:
                flow.send(_make_401(first))

        self.assertIn("kinit", str(ctx.exception).lower())


class DerParserTests(unittest.TestCase):
    """Branch coverage for _der_read_length and _der_signature_oid."""

    def test_long_form_length(self):
        """_der_read_length handles 2-byte long-form length."""
        data = bytes([0x82, 0x01, 0x00]) + b"\x00" * 256
        length, offset = api._der_read_length(data, 0)
        self.assertEqual(length, 256)
        self.assertEqual(offset, 3)

    def test_invalid_indefinite_length_raises(self):
        """_der_read_length raises ValueError for 0x80 (indefinite form)."""
        with self.assertRaises(ValueError):
            api._der_read_length(bytes([0x80]), 0)

    def test_signature_oid_non_sequence_first_child(self):
        """_der_signature_oid returns None when first child of outer SEQUENCE is not 0x30."""
        data = b"\x30\x03\x01\x01\x00"
        self.assertIsNone(api._der_signature_oid(data))

    def test_signature_oid_non_sequence_sigalg(self):
        """_der_signature_oid returns None when signatureAlgorithm field is not SEQUENCE."""
        tbs = b"\x30\x01\x00"
        not_seq = b"\x01\x01\x00"
        inner = tbs + not_seq
        data = b"\x30" + bytes([len(inner)]) + inner
        self.assertIsNone(api._der_signature_oid(data))

    def test_signature_oid_non_oid_tag(self):
        """_der_signature_oid returns None when AlgorithmIdentifier first element is not OID."""
        oid_placeholder = b"\x01\x01\x00"
        alg = b"\x30" + bytes([len(oid_placeholder)]) + oid_placeholder
        tbs = b"\x30\x01\x00"
        inner = tbs + alg
        data = b"\x30" + bytes([len(inner)]) + inner
        self.assertIsNone(api._der_signature_oid(data))

    def test_signature_oid_truncated_data_returns_none(self):
        """_der_signature_oid returns None when DER is truncated (IndexError)."""
        self.assertIsNone(api._der_signature_oid(b"\x30\x05\x30\x03\x30"))


class FinalizeAuthTests(unittest.TestCase):
    """Branch coverage for edge cases in _finalize_mutual_auth."""

    def setUp(self):
        self.patch = _make_fake_client(self)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()

    def test_bare_base64_in_final_response(self):
        """WWW-Authenticate without scheme prefix hits the else-branch (line 373)."""
        auth = api.HttpNegotiateAuth(host="server.example.com", mutual_authentication=False)
        request = httpx2.Request("GET", "https://example.com/")
        flow = auth.auth_flow(request)
        first = next(flow)
        retry = flow.send(_make_401(first))
        bare_b64 = base64.b64encode(b"some-token").decode("ascii")
        with self.assertRaises(StopIteration):
            flow.send(httpx2.Response(
                200,
                headers={"WWW-Authenticate": bare_b64},
                request=retry,
            ))

    def test_invalid_base64_in_final_response(self):
        """Invalid base64 in final WWW-Authenticate is silently ignored (lines 377-378)."""
        auth = api.HttpNegotiateAuth(host="server.example.com", mutual_authentication=False)
        request = httpx2.Request("GET", "https://example.com/")
        flow = auth.auth_flow(request)
        first = next(flow)
        retry = flow.send(_make_401(first))
        with self.assertRaises(StopIteration):
            flow.send(httpx2.Response(
                200,
                headers={"WWW-Authenticate": "Negotiate !!!invalid-base64!!!"},
                request=retry,
            ))


class HttpWarningTest(unittest.TestCase):
    """HTTP scheme triggers a warning (api.py line 416)."""

    def test_http_url_logs_warning(self):
        with _make_fake_client(self) as _:
            auth = api.HttpNegotiateAuth(mutual_authentication=False, host="server")
            request = httpx2.Request("GET", "http://example.com/")
            flow = auth.auth_flow(request)
            first = next(flow)
            with self.assertLogs("httpx2_negotiate_sspi.api", level="WARNING") as cm:
                retry = flow.send(httpx2.Response(
                    401,
                    headers={"WWW-Authenticate": "Negotiate"},
                    request=first,
                ))
                try:
                    flow.send(httpx2.Response(200, request=retry))
                except StopIteration:
                    pass
        self.assertTrue(any("plain http" in m.lower() for m in cm.output))

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
version_module = importlib.import_module("httpx2_negotiate_sspi.__version__")


# ---------------------------------------------------------------------------
# Shared fake infrastructure
# ---------------------------------------------------------------------------


class FakeSSLObject:
    def __init__(self, peercert):
        self.peercert = peercert
        self.binary_form = None

    def getpeercert(self, binary_form=False):
        self.binary_form = binary_form
        return self.peercert


class FakePositionalOnlySSLObject(FakeSSLObject):
    def getpeercert(self, binary_form, /):
        self.binary_form = binary_form
        return self.peercert


class FakeNetworkStream:
    def __init__(self, ssl_object):
        self.ssl_object = ssl_object

    def get_extra_info(self, name):
        if name == "ssl_object":
            return self.ssl_object
        return None


def _make_fake_context_class(test_case):
    """Return a FakeContext class and a list that accumulates created instances."""
    instances = []

    class FakeContext:
        def __init__(self, **create_kwargs):
            self.complete = False
            self.context_attr = spnego.ContextReq(0)
            self.calls: list = []
            self.create_kwargs = create_kwargs
            instances.append(self)

        def step(self, in_token=None):
            self.calls.append(in_token)
            if in_token == b"good":
                self.complete = True
                self.context_attr = spnego.ContextReq.mutual_auth
                return None
            # Return a distinct response token for multi-leg flows
            return "token-{}".format(len(self.calls)).encode()

    test_case.contexts = instances
    return FakeContext


def _start_patches(test_case):
    """Patch spnego.client and socket.getaddrinfo; populate test_case.contexts."""
    FakeContext = _make_fake_context_class(test_case)

    def fake_client(**kwargs):
        return FakeContext(**kwargs)

    patches = [
        mock.patch.object(api.spnego, "client", side_effect=fake_client),
        mock.patch.object(
            api.socket,
            "getaddrinfo",
            return_value=[(None, None, None, "canonical.example.com")],
        ),
    ]
    for p in patches:
        p.start()
    return patches


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class HttpNegotiateAuthTests(unittest.TestCase):
    def setUp(self):
        self.patches = _start_patches(self)

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()

    def test_negotiate_retry_uses_ssl_object_for_channel_binding(self):
        # Channel binding appdata must be "tls-server-end-point:" + SHA-256(cert)
        # for a plain-bytes cert that has no parseable DER signature OID
        # (falls back to SHA-256).
        ssl_object = FakeSSLObject(b"certificate-bytes")
        auth = api.HttpNegotiateAuth(mutual_authentication=False)
        request = httpx2.Request("GET", "https://example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)
        self.assertIs(first_request, request)
        self.assertEqual(first_request.headers["Connection"], "Keep-Alive")

        response = httpx2.Response(
            401,
            headers={"WWW-Authenticate": "Negotiate"},
            request=first_request,
            extensions={"network_stream": FakeNetworkStream(ssl_object)},
        )
        retry_request = flow.send(response)

        self.assertEqual(
            retry_request.headers["Authorization"], "Negotiate dG9rZW4tMQ=="
        )
        self.assertIs(ssl_object.binary_form, True)

        # channel_bindings passed to spnego.client must carry the right appdata
        cb = self.contexts[0].create_kwargs.get("channel_bindings")
        self.assertIsNotNone(cb)
        expected_appdata = (
            b"tls-server-end-point:" + hashlib.sha256(b"certificate-bytes").digest()
        )
        self.assertEqual(cb.application_data, expected_appdata)

        # By default canonicalize_hostname=False → no DNS lookup
        api.socket.getaddrinfo.assert_not_called()

        with self.assertRaises(StopIteration):
            flow.send(httpx2.Response(200, request=retry_request))

    def test_constructor_options_are_passed_to_spnego(self):
        auth = api.HttpNegotiateAuth(
            username="user",
            password="password",
            domain="DOMAIN",
            service="CustomHTTP",
            host="service.example.com",
            delegate=True,
            mutual_authentication=False,
        )
        request = httpx2.Request("GET", "https://ignored.example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)
        retry_request = flow.send(
            httpx2.Response(
                401, headers={"WWW-Authenticate": "Negotiate"}, request=first_request
            )
        )

        ctx = self.contexts[0]
        self.assertEqual(ctx.create_kwargs["hostname"], "service.example.com")
        self.assertEqual(ctx.create_kwargs["service"], "CustomHTTP")
        self.assertEqual(ctx.create_kwargs["username"], "DOMAIN\\user")
        self.assertEqual(ctx.create_kwargs["password"], "password")
        self.assertIn(
            spnego.ContextReq.delegate,
            ctx.create_kwargs["context_req"],
        )
        api.socket.getaddrinfo.assert_not_called()

        with self.assertRaises(StopIteration):
            flow.send(httpx2.Response(200, request=retry_request))

    def test_negotiate_uses_kerberos_protocol_with_gssapi(self):
        auth = api.HttpNegotiateAuth()
        request = httpx2.Request("GET", "http://example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)
        with mock.patch.object(api.sys, "platform", "linux"):
            flow.send(
                httpx2.Response(
                    401,
                    headers={"WWW-Authenticate": "Negotiate"},
                    request=first_request,
                )
            )

        self.assertEqual(self.contexts[0].create_kwargs["protocol"], "kerberos")
        self.assertEqual(
            self.contexts[0].create_kwargs["options"],
            spnego.NegotiateOptions.use_gssapi,
        )

    def test_peer_cert_is_optional(self):
        auth = api.HttpNegotiateAuth()
        request = httpx2.Request("GET", "https://example.com/private")

        self.assertIsNone(auth._get_peer_cert(httpx2.Response(401, request=request)))
        self.assertIsNone(
            auth._get_peer_cert(
                httpx2.Response(
                    401,
                    request=request,
                    extensions={"network_stream": FakeNetworkStream(None)},
                )
            )
        )
        self.assertIsNone(FakeNetworkStream(None).get_extra_info("socket"))

    def test_peer_cert_uses_positional_binary_form_argument(self):
        auth = api.HttpNegotiateAuth()
        request = httpx2.Request("GET", "https://example.com/private")
        ssl_object = FakePositionalOnlySSLObject(b"certificate-bytes")

        peercert = auth._get_peer_cert(
            httpx2.Response(
                401,
                request=request,
                extensions={"network_stream": FakeNetworkStream(ssl_object)},
            )
        )

        self.assertEqual(peercert, b"certificate-bytes")
        self.assertIs(ssl_object.binary_form, True)

    def test_auth_flow_stops_without_supported_challenge(self):
        auth = api.HttpNegotiateAuth()
        request = httpx2.Request("GET", "https://example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)
        with self.assertRaises(StopIteration):
            flow.send(httpx2.Response(200, request=first_request))

        request = httpx2.Request("GET", "https://example.com/private")
        flow = auth.auth_flow(request)
        first_request = next(flow)
        with self.assertRaises(StopIteration):
            flow.send(
                httpx2.Response(
                    401,
                    headers={"WWW-Authenticate": 'Basic realm="example"'},
                    request=first_request,
                )
            )

        self.assertEqual(self.contexts, [])

    def test_auth_flow_stops_when_request_already_has_authorization(self):
        auth = api.HttpNegotiateAuth()
        request = httpx2.Request(
            "GET",
            "https://example.com/private",
            headers={"Authorization": "Bearer token"},
        )
        flow = auth.auth_flow(request)

        first_request = next(flow)
        with self.assertRaises(StopIteration):
            flow.send(
                httpx2.Response(
                    401,
                    headers={"WWW-Authenticate": "Negotiate"},
                    request=first_request,
                )
            )

        self.assertEqual(self.contexts, [])

    def test_canonicalize_hostname_false_does_not_call_getaddrinfo(self):
        # Default: canonicalize_hostname=False
        auth = api.HttpNegotiateAuth(mutual_authentication=False)
        request = httpx2.Request("GET", "https://example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)
        retry_request = flow.send(
            httpx2.Response(
                401, headers={"WWW-Authenticate": "Negotiate"}, request=first_request
            )
        )

        api.socket.getaddrinfo.assert_not_called()
        self.assertEqual(self.contexts[0].create_kwargs["hostname"], "example.com")

        with self.assertRaises(StopIteration):
            flow.send(httpx2.Response(200, request=retry_request))

    def test_canonicalize_hostname_true_calls_getaddrinfo(self):
        auth = api.HttpNegotiateAuth(
            canonicalize_hostname=True, mutual_authentication=False
        )
        request = httpx2.Request("GET", "https://example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)
        retry_request = flow.send(
            httpx2.Response(
                401, headers={"WWW-Authenticate": "Negotiate"}, request=first_request
            )
        )

        api.socket.getaddrinfo.assert_called_once()
        self.assertEqual(
            self.contexts[0].create_kwargs["hostname"], "canonical.example.com"
        )

        with self.assertRaises(StopIteration):
            flow.send(httpx2.Response(200, request=retry_request))

    def test_dns_canonicalization_failure_uses_request_host(self):
        api.socket.getaddrinfo.side_effect = api.socket.gaierror("no canonical name")
        auth = api.HttpNegotiateAuth(
            canonicalize_hostname=True, mutual_authentication=False
        )
        request = httpx2.Request("GET", "https://example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)
        retry_request = flow.send(
            httpx2.Response(
                401, headers={"WWW-Authenticate": "Negotiate"}, request=first_request
            )
        )

        self.assertEqual(self.contexts[0].create_kwargs["hostname"], "example.com")

        with self.assertRaises(StopIteration):
            flow.send(httpx2.Response(200, request=retry_request))

    def test_computed_host_is_not_reused_across_requests(self):
        def canonicalize(host, *args):
            return [(None, None, None, "canonical-{}".format(host))]

        api.socket.getaddrinfo.side_effect = canonicalize
        auth = api.HttpNegotiateAuth(
            canonicalize_hostname=True, mutual_authentication=False
        )

        first_request = httpx2.Request("GET", "https://first.example.com/private")
        first_flow = auth.auth_flow(first_request)
        sent_first = next(first_flow)
        first_retry = first_flow.send(
            httpx2.Response(
                401,
                headers={"WWW-Authenticate": "Negotiate"},
                request=sent_first,
            )
        )
        with self.assertRaises(StopIteration):
            first_flow.send(httpx2.Response(200, request=first_retry))

        second_request = httpx2.Request("GET", "https://second.example.com/private")
        second_flow = auth.auth_flow(second_request)
        sent_second = next(second_flow)
        second_retry = second_flow.send(
            httpx2.Response(
                401,
                headers={"WWW-Authenticate": "Negotiate"},
                request=sent_second,
            )
        )
        with self.assertRaises(StopIteration):
            second_flow.send(httpx2.Response(200, request=second_retry))

        self.assertEqual(
            self.contexts[0].create_kwargs["hostname"],
            "canonical-first.example.com",
        )
        self.assertEqual(
            self.contexts[1].create_kwargs["hostname"],
            "canonical-second.example.com",
        )
        self.assertIsNone(auth._host)

    def test_initial_spnego_error_raises_http_error(self):
        auth = api.HttpNegotiateAuth(host="server.example.com")
        request = httpx2.Request("GET", "https://example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)

        def failing_client(**kwargs):
            class FailingContext:
                complete = False
                context_attr = spnego.ContextReq(0)

                def step(self, in_token=None):
                    raise spnego.exceptions.SpnegoError(error_code=9)

            return FailingContext()

        with mock.patch.object(api.spnego, "client", side_effect=failing_client):
            with self.assertRaises(httpx2.HTTPError):
                flow.send(
                    httpx2.Response(
                        401,
                        headers={"WWW-Authenticate": "Negotiate"},
                        request=first_request,
                    )
                )

    def test_response_spnego_error_raises_http_error(self):
        auth = api.HttpNegotiateAuth(host="server.example.com")
        request = httpx2.Request("GET", "https://example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)

        calls = [0]

        def failing_second_client(**kwargs):
            class FailingSecondContext:
                complete = False
                context_attr = spnego.ContextReq(0)

                def step(self, in_token=None):
                    calls[0] += 1
                    if calls[0] == 1:
                        return b"initial-token"
                    raise spnego.exceptions.SpnegoError(error_code=9)

            return FailingSecondContext()

        with mock.patch.object(api.spnego, "client", side_effect=failing_second_client):
            retry_request = flow.send(
                httpx2.Response(
                    401, headers={"WWW-Authenticate": "NTLM"}, request=first_request
                )
            )
            challenge = base64.b64encode(b"server-challenge").decode("ascii")
            with self.assertRaises(httpx2.HTTPError):
                flow.send(
                    httpx2.Response(
                        401,
                        headers={"WWW-Authenticate": "NTLM {}".format(challenge)},
                        request=retry_request,
                    )
                )

    def test_kerberos_success_finalizes_auth_context(self):
        # A 200 with a good final token must complete the context
        auth = api.HttpNegotiateAuth(host="server.example.com")
        request = httpx2.Request("GET", "https://example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)
        retry_request = flow.send(
            httpx2.Response(
                401, headers={"WWW-Authenticate": "Negotiate"}, request=first_request
            )
        )
        good_b64 = base64.b64encode(b"good").decode("ascii")

        with self.assertRaises(StopIteration):
            flow.send(
                httpx2.Response(
                    200,
                    headers={"WWW-Authenticate": "Negotiate {}".format(good_b64)},
                    request=retry_request,
                )
            )

        self.assertTrue(self.contexts[0].complete)

    def test_initial_challenge_cookie_is_sent_on_retry(self):
        auth = api.HttpNegotiateAuth(
            host="server.example.com", mutual_authentication=False
        )
        request = httpx2.Request("GET", "https://example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)
        retry_request = flow.send(
            httpx2.Response(
                401,
                headers=[
                    ("WWW-Authenticate", "Negotiate"),
                    ("Set-Cookie", "session=one"),
                ],
                request=first_request,
            )
        )

        self.assertEqual(retry_request.headers["Cookie"], "session=one")

        with self.assertRaises(StopIteration):
            flow.send(httpx2.Response(200, request=retry_request))

    def test_ntlm_challenge_response_adds_server_token(self):
        auth = api.HttpNegotiateAuth(
            host="server.example.com", mutual_authentication=False
        )
        request = httpx2.Request("GET", "https://ignored.example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)
        retry_request = flow.send(
            httpx2.Response(
                401, headers={"WWW-Authenticate": "NTLM"}, request=first_request
            )
        )

        challenge = base64.b64encode(b"server-challenge").decode("ascii")
        second_retry_request = flow.send(
            httpx2.Response(
                401,
                headers=[
                    ("WWW-Authenticate", "NTLM {}".format(challenge)),
                    ("Set-Cookie", "session=two"),
                ],
                request=retry_request,
            )
        )

        self.assertEqual(second_retry_request.headers["Cookie"], "session=two")
        # The second step() call receives the decoded server challenge
        self.assertEqual(self.contexts[0].calls[1], b"server-challenge")

        with self.assertRaises(StopIteration):
            flow.send(httpx2.Response(200, request=second_retry_request))

    def test_malformed_ntlm_challenge_raises_httpx_error(self):
        auth = api.HttpNegotiateAuth(host="server.example.com")
        request = httpx2.Request("GET", "https://example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)
        retry_request = flow.send(
            httpx2.Response(
                401, headers={"WWW-Authenticate": "NTLM"}, request=first_request
            )
        )

        with self.assertRaises(httpx2.HTTPError):
            flow.send(
                httpx2.Response(
                    401,
                    headers={"WWW-Authenticate": "NTLM one, NTLM two"},
                    request=retry_request,
                )
            )

    def test_sync_auth_flow_dispatches_retry_request(self):
        auth = api.HttpNegotiateAuth(
            host="server.example.com", mutual_authentication=False
        )
        request = httpx2.Request(
            "POST", "https://example.com/private", content=b"request-body"
        )
        flow = auth.sync_auth_flow(request)

        first_request = next(flow)
        retry_request = flow.send(
            httpx2.Response(
                401,
                headers={"WWW-Authenticate": "Negotiate"},
                content=b"challenge",
                request=first_request,
            )
        )

        self.assertEqual(retry_request.headers["Connection"], "Keep-Alive")
        self.assertIn("Authorization", retry_request.headers)

        with self.assertRaises(StopIteration):
            flow.send(httpx2.Response(200, content=b"ok", request=retry_request))


class VersionTests(unittest.TestCase):
    def test_version_is_exported(self):
        package = importlib.import_module("httpx2_negotiate_sspi")

        self.assertEqual(package.__version__, version_module.__version__)


class HttpNegotiateAuthAsyncTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.patches = _start_patches(self)

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()

    async def test_async_auth_flow_dispatches_retry_request(self):
        auth = api.HttpNegotiateAuth(
            host="server.example.com", mutual_authentication=False
        )
        request = httpx2.Request(
            "POST", "https://example.com/private", content=b"request-body"
        )
        flow = auth.async_auth_flow(request)

        first_request = await flow.__anext__()
        retry_request = await flow.asend(
            httpx2.Response(
                401,
                headers={"WWW-Authenticate": "Negotiate"},
                content=b"challenge",
                request=first_request,
            )
        )

        self.assertEqual(retry_request.headers["Connection"], "Keep-Alive")
        self.assertIn("Authorization", retry_request.headers)

        with self.assertRaises(StopAsyncIteration):
            await flow.asend(
                httpx2.Response(200, content=b"ok", request=retry_request)
            )

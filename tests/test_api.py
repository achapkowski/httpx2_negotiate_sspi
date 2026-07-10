from __future__ import annotations

import base64
import hashlib
import importlib
import sys
import types
import unittest
from types import SimpleNamespace
from unittest import mock

import httpx2


def _install_windows_module_stubs():
    if "pywintypes" not in sys.modules:
        pywintypes = types.ModuleType("pywintypes")
        pywintypes.error = OSError
        sys.modules["pywintypes"] = pywintypes

    for name in ("sspi", "sspicon", "win32security"):
        if name not in sys.modules:
            sys.modules[name] = types.ModuleType(name)


_install_windows_module_stubs()
api = importlib.import_module("httpx2_negotiate_sspi.api")
version_module = importlib.import_module("httpx2_negotiate_sspi.__version__")


class FakeSecBuffer:
    def __init__(self, size, buffer_type):
        self.size = size
        self.buffer_type = buffer_type
        self.Buffer = b""


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


class FakePywinError(Exception):
    def __getitem__(self, index):
        return self.args[index]


def _start_windows_patches(test_case):
    test_case.clients = []

    class FakeClientAuth:
        def __init__(self, scheme, targetspn, auth_info, scflags, datarep):
            self.scheme = scheme
            self.targetspn = targetspn
            self.auth_info = auth_info
            self.scflags = scflags
            self.datarep = datarep
            self.authenticated = False
            self.authorize_calls = []
            self.tokens = iter((b"initial-token", b"response-token"))
            test_case.clients.append(self)

        def authorize(self, sec_buffer):
            self.authorize_calls.append(list(sec_buffer))
            return 0, [SimpleNamespace(Buffer=next(self.tokens))]

    patches = [
        mock.patch.object(
            api.win32security,
            "QuerySecurityPackageInfo",
            return_value={"MaxToken": 4096},
            create=True,
        ),
        mock.patch.object(
            api.win32security, "PySecBufferDescType", side_effect=list, create=True
        ),
        mock.patch.object(
            api.win32security, "PySecBufferType", side_effect=FakeSecBuffer, create=True
        ),
        mock.patch.object(api.sspi, "ClientAuth", FakeClientAuth, create=True),
        mock.patch.object(api.sspicon, "ISC_REQ_MUTUAL_AUTH", 1, create=True),
        mock.patch.object(api.sspicon, "ISC_REQ_DELEGATE", 2, create=True),
        mock.patch.object(api.sspicon, "SECURITY_NETWORK_DREP", 3, create=True),
        mock.patch.object(api.sspicon, "SECBUFFER_CHANNEL_BINDINGS", 4, create=True),
        mock.patch.object(api.sspicon, "SECBUFFER_TOKEN", 5, create=True),
        mock.patch.object(
            api.socket,
            "getaddrinfo",
            return_value=[(None, None, None, "canonical.example.com")],
        ),
    ]
    for patch in patches:
        patch.start()
    return patches


class HttpNegotiateAuthTests(unittest.TestCase):
    def setUp(self):
        self.patches = _start_windows_patches(self)

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()

    def test_negotiate_retry_uses_ssl_object_for_channel_binding(self):
        ssl_object = FakeSSLObject(b"certificate-bytes")
        auth = api.HttpNegotiateAuth()
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
            retry_request.headers["Authorization"], "Negotiate aW5pdGlhbC10b2tlbg=="
        )
        self.assertEqual(self.clients[0].targetspn, "HTTP/canonical.example.com")
        self.assertIs(ssl_object.binary_form, True)

        channel_buffers = [
            sec_buffer
            for sec_buffer in self.clients[0].authorize_calls[0]
            if sec_buffer.buffer_type == api.sspicon.SECBUFFER_CHANNEL_BINDINGS
        ]
        self.assertEqual(len(channel_buffers), 1)
        expected_appdata = (
            b"tls-server-end-point:" + hashlib.sha256(b"certificate-bytes").digest()
        )
        self.assertIn(expected_appdata, channel_buffers[0].Buffer)

        with self.assertRaises(StopIteration):
            flow.send(httpx2.Response(200, request=retry_request))

    def test_constructor_options_are_passed_to_sspi(self):
        auth = api.HttpNegotiateAuth(
            username="user",
            password="password",
            domain="DOMAIN",
            service="CustomHTTP",
            host="service.example.com",
            delegate=True,
        )
        request = httpx2.Request("GET", "https://ignored.example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)
        retry_request = flow.send(
            httpx2.Response(
                401, headers={"WWW-Authenticate": "Negotiate"}, request=first_request
            )
        )

        self.assertEqual(
            retry_request.headers["Authorization"], "Negotiate aW5pdGlhbC10b2tlbg=="
        )
        self.assertEqual(self.clients[0].targetspn, "CustomHTTP/service.example.com")
        self.assertEqual(self.clients[0].auth_info, ("user", "DOMAIN", "password"))
        self.assertEqual(
            self.clients[0].scflags,
            api.sspicon.ISC_REQ_MUTUAL_AUTH | api.sspicon.ISC_REQ_DELEGATE,
        )
        api.socket.getaddrinfo.assert_not_called()

        with self.assertRaises(StopIteration):
            flow.send(httpx2.Response(200, request=retry_request))

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

        self.assertEqual(self.clients, [])

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

        self.assertEqual(self.clients, [])

    def test_dns_canonicalization_failure_uses_request_host(self):
        api.socket.getaddrinfo.side_effect = api.socket.gaierror("no canonical name")
        auth = api.HttpNegotiateAuth()
        request = httpx2.Request("GET", "https://example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)
        retry_request = flow.send(
            httpx2.Response(
                401, headers={"WWW-Authenticate": "Negotiate"}, request=first_request
            )
        )

        self.assertEqual(self.clients[0].targetspn, "HTTP/example.com")

        with self.assertRaises(StopIteration):
            flow.send(httpx2.Response(200, request=retry_request))

    def test_computed_host_is_not_reused_across_requests(self):
        def canonicalize(host, *args):
            return [(None, None, None, f"canonical-{host}")]

        api.socket.getaddrinfo.side_effect = canonicalize
        auth = api.HttpNegotiateAuth()

        first_request = httpx2.Request("GET", "https://first.example.com/private")
        first_flow = auth.auth_flow(first_request)
        sent_first_request = next(first_flow)
        first_retry = first_flow.send(
            httpx2.Response(
                401,
                headers={"WWW-Authenticate": "Negotiate"},
                request=sent_first_request,
            )
        )
        with self.assertRaises(StopIteration):
            first_flow.send(httpx2.Response(200, request=first_retry))

        second_request = httpx2.Request("GET", "https://second.example.com/private")
        second_flow = auth.auth_flow(second_request)
        sent_second_request = next(second_flow)
        second_retry = second_flow.send(
            httpx2.Response(
                401,
                headers={"WWW-Authenticate": "Negotiate"},
                request=sent_second_request,
            )
        )

        self.assertEqual(self.clients[0].targetspn, "HTTP/canonical-first.example.com")
        self.assertEqual(self.clients[1].targetspn, "HTTP/canonical-second.example.com")
        self.assertIsNone(auth._host)

        with self.assertRaises(StopIteration):
            second_flow.send(httpx2.Response(200, request=second_retry))

    def test_initial_sspi_error_stops_retry(self):
        class FailingClientAuth:
            authenticated = False

            def __init__(self, *args, **kwargs):
                pass

            def authorize(self, sec_buffer):
                raise FakePywinError("ignored", "InitializeSecurityContext", "failed")

        auth = api.HttpNegotiateAuth(host="server.example.com")
        request = httpx2.Request("GET", "https://example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)
        with (
            mock.patch.object(api.pywintypes, "error", FakePywinError),
            mock.patch.object(api.sspi, "ClientAuth", FailingClientAuth),
        ):
            with self.assertRaises(StopIteration):
                flow.send(
                    httpx2.Response(
                        401,
                        headers={"WWW-Authenticate": "Negotiate"},
                        request=first_request,
                    )
                )

    def test_response_sspi_error_stops_retry(self):
        test_case = self

        class FailingSecondClientAuth:
            authenticated = False

            def __init__(self, *args, **kwargs):
                self.calls = 0
                test_case.clients.append(self)

            def authorize(self, sec_buffer):
                self.calls += 1
                if self.calls == 1:
                    return 0, [SimpleNamespace(Buffer=b"initial-token")]
                raise FakePywinError("ignored", "InitializeSecurityContext", "failed")

        auth = api.HttpNegotiateAuth(host="server.example.com")
        request = httpx2.Request("GET", "https://example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)
        with (
            mock.patch.object(api.pywintypes, "error", FakePywinError),
            mock.patch.object(api.sspi, "ClientAuth", FailingSecondClientAuth),
        ):
            retry_request = flow.send(
                httpx2.Response(
                    401, headers={"WWW-Authenticate": "NTLM"}, request=first_request
                )
            )
            challenge = base64.b64encode(b"server-challenge").decode("ascii")
            with self.assertRaises(StopIteration):
                flow.send(
                    httpx2.Response(
                        401,
                        headers={"WWW-Authenticate": f"NTLM {challenge}"},
                        request=retry_request,
                    )
                )

    def test_kerberos_success_response_finalizes_auth_context(self):
        auth = api.HttpNegotiateAuth(host="server.example.com")
        request = httpx2.Request("GET", "https://example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)
        retry_request = flow.send(
            httpx2.Response(
                401, headers={"WWW-Authenticate": "Negotiate"}, request=first_request
            )
        )
        final_token = base64.b64encode(b"final-token").decode("ascii")

        with self.assertRaises(StopIteration):
            flow.send(
                httpx2.Response(
                    200,
                    headers={"WWW-Authenticate": f"Negotiate {final_token}"},
                    request=retry_request,
                )
            )

        token_buffers = [
            sec_buffer
            for sec_buffer in self.clients[0].authorize_calls[1]
            if sec_buffer.buffer_type == api.sspicon.SECBUFFER_TOKEN
        ]
        self.assertEqual(token_buffers[-1].Buffer, b"final-token")

    def test_kerberos_final_token_type_error_is_ignored(self):
        auth = api.HttpNegotiateAuth(host="server.example.com")
        request = httpx2.Request("GET", "https://example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)
        retry_request = flow.send(
            httpx2.Response(
                401, headers={"WWW-Authenticate": "Negotiate"}, request=first_request
            )
        )
        final_token = base64.b64encode(b"final-token").decode("ascii")

        with mock.patch.object(
            api.win32security, "PySecBufferType", side_effect=TypeError
        ):
            with self.assertRaises(StopIteration):
                flow.send(
                    httpx2.Response(
                        200,
                        headers={"WWW-Authenticate": f"Negotiate {final_token}"},
                        request=retry_request,
                    )
                )

        self.assertEqual(len(self.clients[0].authorize_calls), 1)

    def test_initial_challenge_cookie_is_sent_on_retry(self):
        auth = api.HttpNegotiateAuth(host="server.example.com")
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

    def test_ntlm_challenge_response_adds_server_token_to_security_buffer(self):
        auth = api.HttpNegotiateAuth(host="server.example.com")
        request = httpx2.Request("GET", "https://ignored.example.com/private")
        flow = auth.auth_flow(request)

        first_request = next(flow)
        retry_request = flow.send(
            httpx2.Response(
                401, headers={"WWW-Authenticate": "NTLM"}, request=first_request
            )
        )
        self.assertEqual(
            retry_request.headers["Authorization"], "NTLM aW5pdGlhbC10b2tlbg=="
        )

        challenge = base64.b64encode(b"server-challenge").decode("ascii")
        second_retry_request = flow.send(
            httpx2.Response(
                401,
                headers=[
                    ("WWW-Authenticate", f"NTLM {challenge}"),
                    ("Set-Cookie", "session=two"),
                ],
                request=retry_request,
            )
        )

        self.assertEqual(
            second_retry_request.headers["Authorization"], "NTLM cmVzcG9uc2UtdG9rZW4="
        )
        self.assertEqual(second_retry_request.headers["Cookie"], "session=two")
        token_buffers = [
            sec_buffer
            for sec_buffer in self.clients[0].authorize_calls[1]
            if sec_buffer.buffer_type == api.sspicon.SECBUFFER_TOKEN
        ]
        self.assertEqual(token_buffers[-1].Buffer, b"server-challenge")

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
        auth = api.HttpNegotiateAuth(host="server.example.com")
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
        self.assertEqual(
            retry_request.headers["Authorization"], "Negotiate aW5pdGlhbC10b2tlbg=="
        )

        with self.assertRaises(StopIteration):
            flow.send(httpx2.Response(200, content=b"ok", request=retry_request))


class VersionTests(unittest.TestCase):
    def test_version_is_exported(self):
        package = importlib.import_module("httpx2_negotiate_sspi")

        self.assertEqual(package.__version__, "2.0.0")
        self.assertEqual(version_module.__version__, "2.0.0")


class HttpNegotiateAuthAsyncTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.patches = _start_windows_patches(self)

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()

    async def test_async_auth_flow_dispatches_retry_request(self):
        auth = api.HttpNegotiateAuth(host="server.example.com")
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
        self.assertEqual(
            retry_request.headers["Authorization"], "Negotiate aW5pdGlhbC10b2tlbg=="
        )

        with self.assertRaises(StopAsyncIteration):
            await flow.asend(httpx2.Response(200, content=b"ok", request=retry_request))

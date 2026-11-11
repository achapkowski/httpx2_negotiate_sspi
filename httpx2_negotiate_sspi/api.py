"""HTTP Negotiate/Kerberos/NTLM authentication for ``httpx2`` via pyspnego.

Works on Windows (through SSPI) and on Linux/macOS (through GSSAPI). The
package name mentions ``sspi`` for historical reasons; the library now supports
all major platforms through the ``pyspnego`` abstraction layer.
"""

from __future__ import annotations
from collections.abc import AsyncGenerator, Generator
import asyncio
import base64
import hashlib
import logging
import socket
import sys
from typing import Any

import httpx2
import spnego
import spnego.channel_bindings
import spnego.exceptions

_logger = logging.getLogger(__name__)

_MAX_HANDSHAKE_ROUNDS = 5

# ---------------------------------------------------------------------------
# RFC 5929 §4.1 — channel-binding hash selection
# ---------------------------------------------------------------------------

# signatureAlgorithm OID -> hashlib name
_OID_TO_HASH: dict[str, str] = {
    "1.2.840.113549.1.1.4": "md5",       # md5WithRSAEncryption
    "1.2.840.113549.1.1.5": "sha1",      # sha1WithRSAEncryption
    "1.2.840.113549.1.1.11": "sha256",   # sha256WithRSAEncryption
    "1.2.840.113549.1.1.12": "sha384",   # sha384WithRSAEncryption
    "1.2.840.113549.1.1.13": "sha512",   # sha512WithRSAEncryption
    "1.2.840.113549.1.1.14": "sha224",   # sha224WithRSAEncryption
    "1.2.840.10045.4.1": "sha1",         # ecdsa-with-SHA1
    "1.2.840.10045.4.3.1": "sha224",     # ecdsa-with-SHA224
    "1.2.840.10045.4.3.2": "sha256",     # ecdsa-with-SHA256
    "1.2.840.10045.4.3.3": "sha384",     # ecdsa-with-SHA384
    "1.2.840.10045.4.3.4": "sha512",     # ecdsa-with-SHA512
    "1.2.840.10040.4.3": "sha1",         # dsa-with-sha1
    "2.16.840.1.101.3.4.3.1": "sha224",  # id-dsa-with-sha224
    "2.16.840.1.101.3.4.3.2": "sha256",  # id-dsa-with-sha256
}

# Promote weak hashes to SHA-256 per RFC 5929 §4.1
_HASH_REMAP: dict[str, str] = {
    "md5": "sha256",
    "sha1": "sha256",
    "sha224": "sha256",
    "sha256": "sha256",
    "sha384": "sha384",
    "sha512": "sha512",
}


def _der_read_length(data: bytes, offset: int) -> tuple[int, int]:
    """Read a DER-encoded length field.

    :returns: ``(length, new_offset)``
    :raises ValueError: On malformed input.
    """
    if data[offset] < 0x80:
        return data[offset], offset + 1
    n = data[offset] & 0x7F
    if n == 0 or offset + 1 + n > len(data):
        raise ValueError("Invalid DER length")
    return int.from_bytes(data[offset + 1 : offset + 1 + n], "big"), offset + 1 + n


def _der_signature_oid(der: bytes) -> str | None:
    """Return the signatureAlgorithm OID of a DER X.509 certificate, or ``None``.

    :param der: DER-encoded certificate bytes.
    :returns: Dotted OID string, or ``None`` if parsing fails.
    """
    try:
        # Outer Certificate SEQUENCE
        if der[0] != 0x30:
            return None
        _, offset = _der_read_length(der, 1)
        # tbsCertificate (first child SEQUENCE) — skip it
        if der[offset] != 0x30:
            return None
        tbs_len, tbs_start = _der_read_length(der, offset + 1)
        offset = tbs_start + tbs_len
        # signatureAlgorithm (second child SEQUENCE)
        if der[offset] != 0x30:
            return None
        _, alg_start = _der_read_length(der, offset + 1)
        # First element of AlgorithmIdentifier: OID tag 0x06
        if der[alg_start] != 0x06:
            return None
        oid_len, oid_start = _der_read_length(der, alg_start + 1)
        raw = der[oid_start : oid_start + oid_len]
        # Decode BER/DER OID bytes
        parts: list[int] = [raw[0] // 40, raw[0] % 40]
        value = 0
        for byte in raw[1:]:
            value = (value << 7) | (byte & 0x7F)
            if not (byte & 0x80):
                parts.append(value)
                value = 0
        return ".".join(str(p) for p in parts)
    except (IndexError, ValueError):
        return None


def _cert_hash_name(der: bytes) -> str:
    """Return the hashlib algorithm name for RFC 5929 channel binding.

    MD5 and SHA-1 (too weak) are promoted to SHA-256 per RFC 5929 §4.1.
    Unknown algorithms (e.g. Ed25519 which has no separate hash) default to
    SHA-256.

    :param der: DER-encoded peer certificate.
    :returns: A hashlib algorithm name such as ``'sha256'`` or ``'sha384'``.
    """
    oid = _der_signature_oid(der)
    hash_name = _OID_TO_HASH.get(oid or "")
    return _HASH_REMAP.get(hash_name or "", "sha256")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class MutualAuthenticationError(httpx2.HTTPError):
    """Raised when the server does not prove its identity.

    With ``mutual_authentication=True`` (the default), the auth flow raises
    this error when the server either omits the final authentication token or
    the token fails to validate.

    NTLM cannot prove the server's identity. Set ``mutual_authentication=False``
    when authenticating against NTLM-only endpoints.
    """


class HttpNegotiateAuth(httpx2.Auth):
    """HTTP Negotiate/NTLM/Kerberos authentication for ``httpx2`` via pyspnego.

    Uses Windows SSPI on Windows and GSSAPI on Linux/macOS. Requires the
    ``sspilib`` extra (installed automatically by ``pyspnego`` on Windows) and
    the ``pyspnego[kerberos]`` extra plus a Kerberos ticket (``kinit``) on
    other platforms.

    A supplied ``host`` is treated as an explicit SPN host override. If omitted,
    the SPN host is computed independently for each challenged request.

    By default, mutual authentication is required (``mutual_authentication=True``)
    and hostname canonicalization is disabled (``canonicalize_hostname=False``).
    NTLM users must set ``mutual_authentication=False`` because NTLM cannot
    prove the server's identity.
    """

    requires_request_body = True
    requires_response_body = True

    _credentials: tuple[str, str] | None = None
    _service: str = "HTTP"
    _host: str | None = None
    _delegate: bool = False
    _mutual_authentication: bool = True
    _canonicalize_hostname: bool = False

    def __init__(
        self,
        username: str | None = None,
        password: str | None = None,
        domain: str | None = None,
        service: str | None = None,
        host: str | None = None,
        delegate: bool = False,
        mutual_authentication: bool = True,
        canonicalize_hostname: bool = False,
    ) -> None:
        """Create a new Negotiate auth handler.

        :param username: Username.
        :param password: Password.
        :param domain: NT domain name. Defaults to ``'.'`` for a local account.
            When set to something other than ``'.'``, it is prepended to
            ``username`` as ``DOMAIN\\username`` unless the username already
            contains ``\\`` or ``@``.
        :param service: Kerberos service class for the remote SPN. Defaults to
            ``'HTTP'``.
        :param host: Host name for the SPN. When omitted, each challenged
            request computes its own SPN host from the request URI.
        :param delegate: Whether the user's credentials may be delegated to the
            server. Enable this only when the remote service is trusted to act on
            the caller's behalf.
        :param mutual_authentication: Require the server to prove its identity.
            When ``True`` (the default), the auth flow raises
            :exc:`MutualAuthenticationError` if the server does not send a valid
            final token. Set to ``False`` for NTLM, which cannot prove the
            server's identity. **This is a breaking change from earlier
            versions.**
        :param canonicalize_hostname: Resolve the SPN hostname through DNS
            (``AI_CANONNAME``) to follow CNAME records. Default ``False``
            because DNS canonicalization lets an attacker who controls DNS
            choose the SPN. Set to ``True`` only when CNAME following is
            required. **This is a breaking change from earlier versions.**

        When both ``username`` and ``password`` are provided, explicit
        credentials are used. Otherwise the current Windows logon session (SSPI)
        or the Kerberos ticket cache (GSSAPI) is used, allowing single sign-on.
        """
        if domain is None:
            domain = "."

        self._credentials = None
        self._service = "HTTP"
        self._host = host
        self._delegate = delegate
        self._mutual_authentication = mutual_authentication
        self._canonicalize_hostname = canonicalize_hostname

        if username is not None and password is not None:
            if domain != "." and "\\" not in username and "@" not in username:
                username = "{}\\{}".format(domain, username)
            self._credentials = (username, password)

        if service is not None:
            self._service = service

    def _get_peer_cert(self, response: httpx2.Response) -> bytes | None:
        """Return the TLS peer certificate from an ``httpx2`` response, if any.

        :param response: Challenge or success response from ``httpx2``.
        :returns: The DER-encoded peer certificate bytes, or ``None`` when the
            transport does not expose an SSL object.
        """
        network_stream = response.extensions.get("network_stream")
        if network_stream is None:
            return None
        ssl_object = network_stream.get_extra_info("ssl_object")
        if ssl_object is None:
            return None
        return ssl_object.getpeercert(True)

    def _www_authenticate_values(self, response: httpx2.Response) -> list[str]:
        """Return flattened ``WWW-Authenticate`` header values.

        ``httpx2`` preserves repeated headers, while some servers also place
        multiple challenges in a single comma-separated value. Base64 tokens
        contain no commas, so splitting on comma is safe.

        :param response: Response containing authentication challenges.
        :returns: A list of stripped challenge values.
        """
        values: list[str] = []
        for value in response.headers.get_list("WWW-Authenticate"):
            values.extend(part.strip() for part in value.split(","))
        return values

    def _get_channel_bindings(
        self, response: httpx2.Response
    ) -> spnego.channel_bindings.GssChannelBindings | None:
        """Build the RFC 5929 ``tls-server-end-point`` channel binding, if any.

        Uses the hash of the certificate signature algorithm, promoting MD5 and
        SHA-1 to SHA-256.

        :param response: Response that may contain TLS peer certificate data.
        :returns: :class:`spnego.channel_bindings.GssChannelBindings`, or
            ``None`` for plain-HTTP connections.
        """
        peercert = self._get_peer_cert(response)
        if peercert is None:
            return None
        hash_name = _cert_hash_name(peercert)
        digest = hashlib.new(hash_name, peercert).digest()
        appdata = b"tls-server-end-point:" + digest
        return spnego.channel_bindings.GssChannelBindings(application_data=appdata)

    def _resolve_hostname(self, request: httpx2.Request) -> str:
        """Return the SPN host for this request.

        :param request: The outgoing request.
        :returns: The resolved SPN hostname.
        """
        if self._host is not None:
            return self._host
        host = request.url.host
        if self._canonicalize_hostname:
            try:
                host = socket.getaddrinfo(
                    host, None, 0, 0, 0, socket.AI_CANONNAME
                )[0][3]
            except socket.gaierror as e:
                _logger.info(
                    "Skipping canonicalization of name %s due to error: %s", host, e
                )
        return host

    def _make_context(
        self,
        hostname: str,
        scheme: str,
        channel_bindings: spnego.channel_bindings.GssChannelBindings | None,
    ) -> Any:
        """Create a pyspnego client context.

        :param hostname: The SPN hostname.
        :param scheme: The auth scheme (``'Negotiate'`` or ``'NTLM'``).
        :param channel_bindings: Channel binding data, or ``None``.
        :returns: A pyspnego client context.
        :raises httpx2.HTTPError: If the required backend (SSPI or GSSAPI) is
            unavailable.
        """
        context_req = spnego.ContextReq.mutual_auth
        if self._delegate:
            context_req |= spnego.ContextReq.delegate

        if self._credentials is not None:
            username, password = self._credentials
            options = spnego.NegotiateOptions(0)
        else:
            username = None
            password = None
            if sys.platform == "win32":
                options = spnego.NegotiateOptions.use_sspi
            else:
                options = spnego.NegotiateOptions.use_gssapi

        protocol = scheme.lower()
        if sys.platform != "win32" and protocol == "negotiate":
            protocol = "kerberos"

        try:
            return spnego.client(
                username=username,
                password=password,
                hostname=hostname,
                service=self._service,
                protocol=protocol,
                context_req=context_req,
                options=options,
                channel_bindings=channel_bindings,
            )
        except spnego.exceptions.SpnegoError as e:
            if sys.platform == "win32":
                hint = "Install sspilib"
            else:
                hint = "Install pyspnego[kerberos] and run kinit"
            raise httpx2.HTTPError(
                "SPNEGO backend unavailable: {} ({})".format(e, hint)
            ) from e

    def _finalize_mutual_auth(
        self,
        response: httpx2.Response,
        scheme: str,
        ctx: Any,
    ) -> None:
        """Consume the server's final token and enforce mutual authentication.

        :param response: The final (non-401) server response.
        :param scheme: The authentication scheme name.
        :param ctx: The pyspnego client context.
        :raises MutualAuthenticationError: When :attr:`_mutual_authentication`
            is ``True`` and the server does not prove its identity.
        """
        final_token: bytes | None = None
        www_auth = response.headers.get("WWW-Authenticate", "")
        if www_auth:
            stripped = www_auth.strip()
            # Accept "<scheme> <base64>" or a bare base64 value
            if stripped.lower().startswith(scheme.lower() + " "):
                b64 = stripped[len(scheme) + 1 :].strip()
            else:
                b64 = stripped
            if b64:
                try:
                    final_token = base64.b64decode(b64)
                except Exception:
                    final_token = None

        final_token_processed = False
        if final_token is not None and not ctx.complete:
            try:
                ctx.step(final_token)
                final_token_processed = True
            except (spnego.exceptions.SpnegoError, ValueError) as e:
                _logger.debug("Final token step failed: %s", e)

        if self._mutual_authentication and not (
            ctx.complete
            and final_token_processed
            and (getattr(ctx, "context_attr", 0) or 0) & spnego.ContextReq.mutual_auth
        ):
            raise MutualAuthenticationError(
                "Mutual authentication failed: server did not prove its identity"
            )

    def _retry_using_http_Negotiate_auth(
        self,
        response: httpx2.Response,
        scheme: str,
    ) -> Generator[httpx2.Request, httpx2.Response, None]:
        """Drive the challenge-response handshake for a single auth scheme.

        :param response: Initial ``401 Unauthorized`` response from the server.
        :param scheme: Advertised authentication scheme to use.
        :yields: Follow-up requests with updated ``Authorization`` headers.
        :raises MutualAuthenticationError: When :attr:`_mutual_authentication`
            is ``True`` and the server does not send a valid final token.
        :raises httpx2.HTTPError: If the handshake exceeds
            :data:`_MAX_HANDSHAKE_ROUNDS`, the SPNEGO backend is unavailable,
            or the server returns an invalid challenge.
        """
        request = response.request

        if "Authorization" in request.headers:
            return None

        if request.url.scheme == "http":
            _logger.warning(
                "HTTP Negotiate over plain HTTP: content is not protected and "
                "channel binding is not available."
            )

        hostname = self._resolve_hostname(request)
        channel_bindings = self._get_channel_bindings(response)
        ctx = self._make_context(hostname, scheme, channel_bindings)

        try:
            out_token = ctx.step()
        except spnego.exceptions.SpnegoError as e:
            raise httpx2.HTTPError("SPNEGO step failed: {}".format(e)) from e

        request.headers["Authorization"] = "{} {}".format(
            scheme, base64.b64encode(out_token).decode("ASCII")
        )
        if response.cookies:
            httpx2.Cookies(response.cookies).set_cookie_header(request=request)

        response2 = yield request

        # Multi-leg handshake (e.g. NTLM: initial → challenge → response)
        rounds = 1
        while response2.status_code == 401 and not ctx.complete:
            if rounds >= _MAX_HANDSHAKE_ROUNDS:
                raise httpx2.HTTPError(
                    "HTTP Negotiate handshake exceeded {} rounds.".format(
                        _MAX_HANDSHAKE_ROUNDS
                    )
                )

            challenge_values = [
                val[len(scheme) + 1 :]
                for val in self._www_authenticate_values(response2)
                if val.lower().startswith(scheme.lower() + " ")
            ]
            if len(challenge_values) != 1:
                raise httpx2.HTTPError(
                    "Did not get exactly one {} challenge from server.".format(scheme)
                )

            try:
                in_token = base64.b64decode(challenge_values[0])
                out_token = ctx.step(in_token)
            except (spnego.exceptions.SpnegoError, ValueError) as e:
                raise httpx2.HTTPError("SPNEGO step failed: {}".format(e)) from e

            if out_token is None:
                break

            request.headers["Authorization"] = "{} {}".format(
                scheme, base64.b64encode(out_token).decode("ASCII")
            )
            if response2.cookies:
                httpx2.Cookies(response2.cookies).set_cookie_header(request=request)

            response2 = yield request
            rounds += 1

        # First non-401 response: finalize auth context
        if response2.status_code != 401:
            self._finalize_mutual_auth(response2, scheme, ctx)
            return

    def auth_flow(
        self, request: httpx2.Request
    ) -> Generator[httpx2.Request, httpx2.Response, None]:
        """Run the shared Negotiate/NTLM authentication state machine.

        ``httpx2`` drives this generator by sending each yielded request and
        passing the resulting response back in. Use ``sync_auth_flow`` and
        ``async_auth_flow`` through ``httpx2.Client`` or
        ``httpx2.AsyncClient``; this method exists as the shared
        implementation for both client modes.

        :param request: Initial request created by the caller.
        :yields: The original request, followed by any retry requests needed to
            complete the HTTP authentication exchange.
        :raises MutualAuthenticationError: When :attr:`_mutual_authentication`
            is ``True`` and the server cannot prove its identity.
        :raises httpx2.HTTPError: If the server returns an invalid challenge
            sequence or the SPNEGO backend is unavailable.

        The flow adds ``Connection: Keep-Alive`` to the outgoing request, stops
        immediately when the response is not ``401``, and tries ``Negotiate``
        before ``NTLM`` when both are advertised.
        """
        request.headers["Connection"] = "Keep-Alive"

        response = yield request

        if response.status_code != 401:
            return

        for scheme in ("Negotiate", "NTLM"):
            if any(
                value.lower().startswith(scheme.lower())
                for value in self._www_authenticate_values(response)
            ):
                yield from self._retry_using_http_Negotiate_auth(response, scheme)
                return

    def sync_auth_flow(
        self, request: httpx2.Request
    ) -> Generator[httpx2.Request, httpx2.Response, None]:
        """Authenticate a request for ``httpx2.Client``.

        Request and response bodies are read before the SPNEGO handshake
        advances so retry requests can be sent safely.

        :param request: Request created by ``httpx2.Client``.
        :yields: Requests that should be sent synchronously.
        """
        request.read()

        flow = self.auth_flow(request)
        request = next(flow)

        while True:
            response = yield request
            response.read()

            try:
                request = flow.send(response)
            except StopIteration:
                break

    async def async_auth_flow(
        self, request: httpx2.Request
    ) -> AsyncGenerator[httpx2.Request, httpx2.Response]:
        """Authenticate a request for ``httpx2.AsyncClient``.

        SSPI/GSSAPI calls and DNS lookups execute in a worker thread so the
        event loop is not blocked.

        :param request: Request created by ``httpx2.AsyncClient``.
        :yields: Requests that should be sent asynchronously.
        """
        await request.aread()

        flow = self.auth_flow(request)
        request = next(flow)

        # StopIteration cannot propagate through asyncio.to_thread (PEP 479
        # converts it to RuntimeError inside a coroutine). Catch it in the
        # thread worker and return a sentinel instead.
        _done = object()

        def _send(response: httpx2.Response) -> httpx2.Request | object:
            try:
                return flow.send(response)
            except StopIteration:
                return _done

        while True:
            response = yield request
            await response.aread()

            result = await asyncio.to_thread(_send, response)
            if result is _done:
                break
            request = result  # type: ignore[assignment]

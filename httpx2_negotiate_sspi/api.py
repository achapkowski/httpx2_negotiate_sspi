"""Windows SSPI-backed HTTP Negotiate authentication for ``httpx2``.

This module exposes :class:`HttpNegotiateAuth`, a small ``httpx2.Auth``
implementation that drives the SSPI challenge-response handshake for
``Negotiate`` and ``NTLM`` HTTP authentication.

The implementation is intentionally Windows-specific because it depends on the
SSPI interfaces provided by ``pywin32``. When the transport exposes an SSL
object in the response extensions, the auth flow includes a TLS channel
binding token derived from the peer certificate so it can interoperate with
servers that require Extended Protection for Authentication.
"""

from __future__ import annotations
from collections.abc import AsyncGenerator, Generator
import base64
import hashlib
import logging
import socket
import struct
from typing import Any

import httpx2

import pywintypes
import sspi
import sspicon
import win32security

_logger = logging.getLogger(__name__)


class HttpNegotiateAuth(httpx2.Auth):
    """HTTP Negotiate authentication for ``httpx2`` clients using Windows SSPI.

    The auth object supports both ``httpx2.Client`` and ``httpx2.AsyncClient``.
    It handles ``Negotiate`` and ``NTLM`` challenges, builds SSPI tokens with
    either default Windows credentials or explicit credentials, and includes TLS
    channel binding data when the transport exposes an SSL object.

    A supplied ``host`` is treated as an explicit SPN host override. If omitted,
    the SPN host is computed independently for each challenged request.

    Use this auth class for Windows clients that need Kerberos or NTLM over
    HTTP. Avoid it for non-Windows runtimes or for services that expect a
    different authentication scheme entirely.
    """

    requires_request_body = True
    requires_response_body = True

    _auth_info: tuple[str, str, str] | None = None
    _service: str = "HTTP"
    _host: str | None = None
    _delegate: bool = False

    def __init__(
        self,
        username: str | None = None,
        password: str | None = None,
        domain: str | None = None,
        service: str | None = None,
        host: str | None = None,
        delegate: bool = False,
    ) -> None:
        """Create a new Negotiate auth handler.

        :param username: Username.
        :param password: Password.
        :param domain: NT domain name. Defaults to ``'.'`` for a local account.
        :param service: Kerberos service type for the remote SPN. Defaults to ``'HTTP'``.
        :param host: Host name for the SPN. When omitted, each challenged request
            computes its own SPN host from the request URI and may canonicalize it
            through DNS.
        :param delegate: Whether the user's credentials may be delegated to the
            server. Enable this only when the remote service is trusted to act on
            the caller's behalf.

        Explicit credentials are used only when both ``username`` and ``password``
        are provided. Otherwise the current Windows logon credentials are used,
        which allows single sign-on to domain resources for interactive users and
        service accounts.
        """
        if domain is None:
            domain = "."

        self._auth_info = None
        self._service = "HTTP"
        self._host = host
        self._delegate = delegate

        if username is not None and password is not None:
            self._auth_info = (username, domain, password)

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
        multiple challenges in a single comma-separated value. This helper
        normalizes both cases so the auth flow can inspect each advertised
        scheme individually.

        :param response: Response containing authentication challenges.
        :returns: A list of stripped challenge values.
        """
        values: list[str] = []
        for value in response.headers.get_list("WWW-Authenticate"):
            values.extend(part.strip() for part in value.split(","))
        return values

    def _set_auth_header(
        self,
        request: httpx2.Request,
        response: httpx2.Response,
        scheme: str,
        clientauth: Any,
        sec_buffer: Any,
        message: str,
    ) -> None:
        """Generate the next SSPI token and attach it to the request.

        :param request: Request being retried.
        :param response: Response that triggered the retry.
        :param scheme: Authentication scheme name, usually ``Negotiate`` or
            ``NTLM``.
        :param clientauth: Active SSPI client context.
        :param sec_buffer: Security buffer list sent to SSPI.
        :param message: Log message describing the handshake step.
        :raises pywintypes.error: Propagated from ``clientauth.authorize``.

        Any cookies set on the challenge response are copied to the retry
        request so the authentication exchange preserves server affinity.
        """
        error, auth = clientauth.authorize(sec_buffer)
        request.headers["Authorization"] = "{} {}".format(
            scheme, base64.b64encode(auth[0].Buffer).decode("ASCII")
        )
        if response.cookies:
            httpx2.Cookies(response.cookies).set_cookie_header(request=request)
        _logger.debug(
            "%s - error=%s authenticated=%s", message, error, clientauth.authenticated
        )

    def _append_token_buffer(
        self, sec_buffer: Any, max_token: int, token: str | bytes
    ) -> None:
        """Decode a server token and append it to the SSPI buffer list.

        :param sec_buffer: Security buffer descriptor passed to SSPI.
        :param max_token: Maximum token size reported by the security package.
        :param token: Base64-encoded or raw token bytes from the server.
        """
        tokenbuf = win32security.PySecBufferType(max_token, sspicon.SECBUFFER_TOKEN)
        if isinstance(token, str):
            token = token.encode("ASCII")
        tokenbuf.Buffer = base64.b64decode(token)
        sec_buffer.append(tokenbuf)

    def _retry_using_http_Negotiate_auth(
        self,
        response: httpx2.Response,
        scheme: str,
    ) -> Generator[httpx2.Request, httpx2.Response, None]:
        """Drive the challenge-response handshake for a single auth scheme.

        :param response: Initial ``401 Unauthorized`` response from the server.
        :param scheme: Advertised authentication scheme to use.
        :yields: Follow-up requests with updated ``Authorization`` headers.
        :raises httpx2.HTTPError: If the server returns an invalid NTLM challenge
            sequence.

        The method is conservative about retries. If the outgoing request
        already contains an ``Authorization`` header, or if SSPI fails to
        generate a token, the handshake is abandoned and control returns to
        ``httpx2`` without overwriting the existing request state.
        """
        request = response.request

        if "Authorization" in request.headers:
            return None

        host = self._host
        if host is None:
            host = request.url.host
            try:
                host = socket.getaddrinfo(host, None, 0, 0, 0, socket.AI_CANONNAME)[0][
                    3
                ]
            except socket.gaierror as e:
                _logger.info(
                    "Skipping canonicalization of name %s due to error: %s", host, e
                )

        targetspn = "{}/{}".format(self._service, host)

        # We request mutual auth by default
        scflags = sspicon.ISC_REQ_MUTUAL_AUTH

        if self._delegate:
            scflags |= sspicon.ISC_REQ_DELEGATE

        # Set up SSPI connection structure
        pkg_info = win32security.QuerySecurityPackageInfo(scheme)
        clientauth = sspi.ClientAuth(
            scheme,
            targetspn=targetspn,
            auth_info=self._auth_info,
            scflags=scflags,
            datarep=sspicon.SECURITY_NETWORK_DREP,
        )
        sec_buffer = win32security.PySecBufferDescType()

        # Channel Binding Hash (aka Extended Protection for Authentication)
        # If this is a SSL connection, we need to hash the peer certificate, prepend the RFC5929 channel binding type,
        # and stuff it into a SEC_CHANNEL_BINDINGS structure.
        # This should be sent along in the initial handshake or Kerberos auth will fail.
        peercert = self._get_peer_cert(response)
        if peercert is not None:
            md = hashlib.sha256()
            md.update(peercert)
            appdata = "tls-server-end-point:".encode("ASCII") + md.digest()
            cbtbuf = win32security.PySecBufferType(
                pkg_info["MaxToken"], sspicon.SECBUFFER_CHANNEL_BINDINGS
            )
            cbtbuf.Buffer = struct.pack(
                "LLLLLLLL{}s".format(len(appdata)),
                0,
                0,
                0,
                0,
                0,
                0,
                len(appdata),
                32,
                appdata,
            )
            sec_buffer.append(cbtbuf)

        # Send initial challenge auth header
        try:
            self._set_auth_header(
                request,
                response,
                scheme,
                clientauth,
                sec_buffer,
                "Sending Initial Context Token",
            )
        except pywintypes.error as e:
            _logger.debug("Error calling {}: {}".format(e[1], e[2]), exc_info=e)
            return None

        response2 = yield request

        # Should get another 401 if we are doing challenge-response (NTLM)
        if response2.status_code != 401:
            # Kerberos may have succeeded; if so, finalize our auth context
            final = response2.headers.get("WWW-Authenticate")
            if final is not None:
                try:
                    # Sometimes Windows seems to forget to prepend 'Negotiate' to the success response,
                    # and we get just a bare chunk of base64 token. Not sure why.
                    final = final.replace(scheme, "", 1).lstrip()
                    self._append_token_buffer(sec_buffer, pkg_info["MaxToken"], final)
                    error, auth = clientauth.authorize(sec_buffer)
                    _logger.debug(
                        "Kerberos Authentication succeeded - error={} authenticated={}".format(
                            error, clientauth.authenticated
                        )
                    )
                except TypeError:
                    pass

            # Regardless of whether or not we finalized our auth context,
            # without a 401 we've got nothing to do. Update the history and return.
            return

        # Extract challenge message from server
        challenge = [
            val[len(scheme) + 1 :]
            for val in self._www_authenticate_values(response2)
            if val.lower().startswith(scheme.lower() + " ")
        ]
        if len(challenge) != 1:
            raise httpx2.HTTPError(
                "Did not get exactly one {} challenge from server.".format(scheme)
            )

        # Add challenge to security buffer
        self._append_token_buffer(sec_buffer, pkg_info["MaxToken"], challenge[0])
        _logger.debug("Got Challenge Token (NTLM)")

        # Perform next authorization step
        try:
            self._set_auth_header(
                request, response2, scheme, clientauth, sec_buffer, "Sending Response"
            )
        except pywintypes.error as e:
            _logger.debug("Error calling {}: {}".format(e[1], e[2]), exc_info=e)
            return

        yield request

    def auth_flow(
        self, request: httpx2.Request
    ) -> Generator[httpx2.Request, httpx2.Response, None]:
        """Run the shared Negotiate/NTLM authentication state machine.

        ``httpx2`` drives this generator by sending each yielded request and
        passing the resulting response back in. Use ``sync_auth_flow`` and
        ``async_auth_flow`` through ``httpx2.Client`` or ``httpx2.AsyncClient``;
        this method exists as the shared implementation for both client modes.

        :param request: Initial request created by the caller.
        :yields: The original request, followed by any retry requests needed to
            complete the HTTP authentication exchange.
        :raises httpx2.HTTPError: If the server returns an invalid NTLM
            challenge sequence.

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

        Request and response bodies are read before the SSPI handshake advances
        so retry requests can be sent safely through ``httpx2``'s auth flow.

        :param request: Request created by ``httpx2.Client``.
        :yields: Requests that should be sent synchronously.

        Reading the bodies eagerly ensures that replayed requests do not depend
        on unread streams that may no longer be available when the server
        challenges the original request.
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

        The Windows SSPI calls are synchronous, but this async generator follows
        ``httpx2``'s async auth contract and awaits request and response body
        reads before advancing the shared handshake.

        :param request: Request created by ``httpx2.AsyncClient``.
        :yields: Requests that should be sent asynchronously.

        Just like ``sync_auth_flow``, this eagerly reads request and response
        bodies so the authentication retry sequence can safely resend the
        request after a ``401`` challenge.
        """
        await request.aread()

        flow = self.auth_flow(request)
        request = next(flow)

        while True:
            response = yield request
            await response.aread()

            try:
                request = flow.send(response)
            except StopIteration:
                break

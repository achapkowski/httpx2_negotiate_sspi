Usage Guide
===========

The public API consists of :class:`httpx2_negotiate_sspi.HttpNegotiateAuth`.
It works with both :class:`httpx2.Client` and :class:`httpx2.AsyncClient`.

Configuration options
---------------------

``username`` / ``password``
   Explicit credentials. Both must be provided together; if either is omitted
   the current session credentials (Windows SSPI logon session or Kerberos
   ticket cache) are used for single sign-on.

``domain``
   NT domain name for explicit credentials. Defaults to ``"."`` (local
   account). When set to something other than ``"."`` and the username does not
   already contain ``\\`` or ``@``, the domain is prepended as
   ``DOMAIN\\username``.

``service``
   Kerberos service class used to build the SPN. Defaults to ``"HTTP"``.

``host``
   Explicit SPN host override. When provided it is always used as-is and DNS
   canonicalization is skipped regardless of ``canonicalize_hostname``.

``delegate``
   Enables credential delegation (``ISC_REQ_DELEGATE`` / GS2 delegation).
   Only enable this when the remote service is trusted to act on the caller's
   behalf (double-hop scenarios).

``mutual_authentication`` *(default: True)*
   Require the server to prove its identity. When ``True`` (the default), the
   auth flow raises :exc:`~httpx2_negotiate_sspi.MutualAuthenticationError` if
   the server does not send a valid final authentication token.

   **NTLM cannot prove the server's identity.** Set this to ``False`` when
   authenticating against NTLM-only endpoints:

   .. code-block:: python

      auth = HttpNegotiateAuth(mutual_authentication=False)

``canonicalize_hostname`` *(default: False)*
   Resolve the SPN hostname through DNS (``AI_CANONNAME``) to follow CNAME
   records. Disabled by default because an attacker who controls DNS can
   choose the SPN. Enable only when CNAME following is required:

   .. code-block:: python

      auth = HttpNegotiateAuth(canonicalize_hostname=True)

Security — always use HTTPS
---------------------------

HTTP Negotiate authenticates only the initial handshake. It does not protect
the content of subsequent requests or responses. On plain HTTP there is also no
TLS channel binding, which makes relay attacks easier.

The library logs a ``WARNING`` when the request URL scheme is ``http``.

Mutual authentication
---------------------

With ``mutual_authentication=True`` (the default) the library verifies that:

1. The SPNEGO context is ``complete`` after the final server token.
2. The ``mutual_auth`` flag is set in the negotiated context attributes.

If either check fails, :exc:`~httpx2_negotiate_sspi.MutualAuthenticationError`
is raised. This is a subclass of :exc:`httpx2.HTTPError`.

When the server advertises only ``NTLM``, the library raises
:exc:`~httpx2_negotiate_sspi.MutualAuthenticationError` at scheme selection —
before ``spnego.client`` is called and before any credential token is
generated or sent. This is a fail-secure guarantee: a malicious server
advertising only NTLM cannot obtain the user's credential-derived response.

Set ``mutual_authentication=False`` for NTLM-only endpoints where you accept
this limitation:

SPN and hostname canonicalization
----------------------------------

The SPN is constructed as ``<service>/<host>``, e.g. ``HTTP/server.contoso.com``.

- If ``host=`` is provided, it is always used as-is.
- If ``canonicalize_hostname=False`` (the default), ``request.url.host`` is
  used directly.
- If ``canonicalize_hostname=True``, the host is resolved through
  ``socket.getaddrinfo(..., AI_CANONNAME)``. The original host is used as a
  fallback if DNS fails.

.. code-block:: python

   from httpx2_negotiate_sspi import HttpNegotiateAuth

   # Explicit SPN host override
   auth = HttpNegotiateAuth(host="adfs.contoso.com")

   # Enable CNAME following
   auth = HttpNegotiateAuth(canonicalize_hostname=True)

Channel binding and Extended Protection
---------------------------------------

When the ``httpx2`` transport exposes an SSL object in the response extensions,
the library automatically derives a ``tls-server-end-point`` channel binding
token from the TLS peer certificate (RFC 5929).

The hash algorithm follows RFC 5929 §4.1: use the hash of the certificate's
signature algorithm, promoting MD5 and SHA-1 to SHA-256.

This enables interoperability with services that enforce Extended Protection
for Authentication (IIS, ADFS). No configuration is required; the channel
binding is included automatically over HTTPS and omitted over plain HTTP.

Challenge-response behavior
---------------------------

- ``Connection: Keep-Alive`` is added to outgoing requests.
- ``Negotiate`` is attempted before ``NTLM`` when both are advertised.
- An existing ``Authorization`` header suppresses automatic retries.
- Cookies set on challenge responses are copied to retry requests.
- The handshake is capped at five rounds; exceeding the limit raises
  :exc:`httpx2.HTTPError`.

Failure modes
-------------

- If the server does not advertise ``Negotiate`` or ``NTLM``, the auth flow
  stops without retrying.
- If mutual authentication is required but the server does not prove its
  identity, :exc:`~httpx2_negotiate_sspi.MutualAuthenticationError` is raised.
- If the SPNEGO backend (SSPI or GSSAPI) is unavailable,
  :exc:`httpx2.HTTPError` is raised with a hint about the missing dependency.
- If the server returns an invalid challenge sequence,
  :exc:`httpx2.HTTPError` is raised.

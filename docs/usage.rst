Usage Guide
===========

The public API consists of :class:`httpx2_negotiate_sspi.HttpNegotiateAuth`.
It works with both :class:`httpx2.Client` and :class:`httpx2.AsyncClient`.

Configuration options
---------------------

``HttpNegotiateAuth`` accepts the following options:

``username`` / ``password``
   Explicit credentials for the SSPI client context. Both values must be
   present or the current Windows logon credentials remain in use.

``domain``
   NT domain name paired with explicit credentials. Defaults to ``"."`` so a
   local machine account can be referenced when needed.

``service``
   Kerberos service class used to build the SPN. The default is ``"HTTP"``.

``host``
   Explicit SPN host override. When omitted, the request host is used and may
   be canonicalized with DNS for each challenged request.

``delegate``
   Enables delegated credentials by setting ``ISC_REQ_DELEGATE``. Only enable
   this when the remote service is trusted to act on behalf of the caller.

SPN selection
-------------

When ``host`` is not provided, the auth flow derives the SPN host from the
request URL. It then attempts DNS canonicalization. If canonicalization fails,
the original request host is used instead.

This behavior matters when the HTTP endpoint and the Kerberos SPN do not share
the same canonical host name. In those cases, pass an explicit ``host`` value.

.. code-block:: python

   from httpx2_negotiate_sspi import HttpNegotiateAuth

   auth = HttpNegotiateAuth(service="HTTP", host="adfs.contoso.com")

Channel binding and Extended Protection
---------------------------------------

If the ``httpx2`` transport exposes an SSL object in the response extensions,
the auth flow hashes the TLS peer certificate and sends the resulting channel
binding token to SSPI.

This enables interoperability with services that enforce Extended Protection
for Authentication, such as hardened IIS or ADFS deployments. If no SSL object
is available, the auth flow continues without a channel binding token.

Challenge-response behavior
---------------------------

- The flow adds ``Connection: Keep-Alive`` to the request.
- ``Negotiate`` is attempted before ``NTLM`` when both are advertised.
- Existing ``Authorization`` headers are preserved and suppress automatic
  Negotiate retries.
- Cookies set on challenge responses are copied to retry requests.
- Kerberos success responses may include a final token without another
  ``401 Unauthorized`` challenge, and the auth context is finalized when
  possible.

Failure modes
-------------

- If the server does not advertise ``Negotiate`` or ``NTLM``, the auth flow
  stops without retrying.
- If the server returns an invalid NTLM challenge sequence, the flow raises
  :class:`httpx2.HTTPError`.
- If SSPI fails to generate a token, the handshake stops and the auth flow
  returns control to the caller without forcing another retry.

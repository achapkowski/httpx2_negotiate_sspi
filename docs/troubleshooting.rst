Troubleshooting
===============

401 Unauthorized — authentication not attempted
------------------------------------------------

The auth flow only retries for ``Negotiate`` or ``NTLM`` schemes. Confirm the
server is advertising one of those in the ``WWW-Authenticate`` response header.

``MutualAuthenticationError`` raised against an NTLM server
------------------------------------------------------------

NTLM cannot prove the server's identity, so it always fails the mutual
authentication check. Set ``mutual_authentication=False``:

.. code-block:: python

   auth = HttpNegotiateAuth(mutual_authentication=False)

``MutualAuthenticationError`` raised against a Kerberos server
--------------------------------------------------------------

The server did not send a valid final token. Possible causes:

- The server does not send a ``WWW-Authenticate`` header on the final
  ``200 OK``. Some load balancers strip it. Contact the server administrator.
- The token the server sent failed validation. This is unusual and may
  indicate a misconfigured Kerberos deployment.

If you need to work around a known non-compliant server:

.. code-block:: python

   auth = HttpNegotiateAuth(mutual_authentication=False)

Kerberos works only with an explicit host override
--------------------------------------------------

The library uses ``request.url.host`` as the SPN host by default
(``canonicalize_hostname=False``). If the SPN registered in Active Directory
does not match that host, Kerberos fails.

Options:

1. Pass the exact SPN host explicitly:

   .. code-block:: python

      auth = HttpNegotiateAuth(host="adfs.contoso.com")

2. Enable DNS canonicalization to follow CNAME records:

   .. code-block:: python

      auth = HttpNegotiateAuth(canonicalize_hostname=True)

Linux/macOS — no Kerberos ticket
---------------------------------

Obtain a ticket before making requests:

.. code-block:: console

   kinit user@REALM.COM
   klist   # confirm a valid ticket is listed

If ``klist`` shows no tickets, authentication will fail even if credentials
are correct.

Linux/macOS — GSSAPI library not found
---------------------------------------

System Kerberos libraries must be installed before ``pip install``:

.. code-block:: console

   # Ubuntu / Debian
   sudo apt install libkrb5-dev

   # macOS
   brew install krb5

If the libraries were installed after the Python package, reinstall:

.. code-block:: console

   pip install --force-reinstall pyspnego[kerberos]

Explicit credentials not used
------------------------------

Both ``username`` and ``password`` must be provided together. If either is
omitted, the SSPI logon session or Kerberos ticket cache is used instead.

Extended Protection required by the server
------------------------------------------

Use HTTPS. The library derives a ``tls-server-end-point`` channel binding
token from the TLS peer certificate automatically when the ``httpx2``
transport exposes an SSL object. No configuration is needed.

An ``Authorization`` header is already present
----------------------------------------------

If the outgoing request already contains an ``Authorization`` header, the
Negotiate flow does not replace it. Remove or avoid pre-setting that header.

Invalid NTLM challenge errors
-----------------------------

The flow expects exactly one NTLM challenge token in the follow-up
``WWW-Authenticate`` response. Multiple or malformed NTLM challenge values
raise :exc:`httpx2.HTTPError`.

NTLM fails between the first and second request
------------------------------------------------

NTLM requires both legs of the handshake to travel on the same TCP connection.
If the connection is closed between requests (e.g. by a proxy or load
balancer), the handshake fails. Use HTTPS with a persistent transport or
switch to Kerberos.

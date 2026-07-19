Troubleshooting
===============

Authentication keeps returning 401
----------------------------------

Check that the server is advertising either ``Negotiate`` or ``NTLM`` in the
``WWW-Authenticate`` response header. The auth flow only retries for those
schemes.

Explicit credentials do not appear to be used
---------------------------------------------

Provide both ``username`` and ``password``. If either value is missing, the
auth flow keeps using the current Windows logon credentials.

Kerberos works only with an explicit host override
--------------------------------------------------

The library computes the SPN host from the request URL and attempts DNS
canonicalization per challenged request. If that produces a host name that does
not match the service principal registered on the server, pass ``host=...``
explicitly.

Extended Protection is required by the server
---------------------------------------------

Use HTTPS and make sure the ``httpx2`` transport exposes an SSL object through
the response extensions. When present, ``httpx2-negotiate-sspi`` derives a TLS
channel binding token from the peer certificate.

An Authorization header is already present
------------------------------------------

If the request already contains ``Authorization``, the Negotiate flow does not
replace it. Remove or avoid setting that header if you want SSPI negotiation to
run automatically.

Invalid NTLM challenge errors
-----------------------------

The flow expects exactly one NTLM challenge token in the follow-up
``WWW-Authenticate`` response. Multiple or malformed NTLM challenge values
raise :class:`httpx2.HTTPError`.

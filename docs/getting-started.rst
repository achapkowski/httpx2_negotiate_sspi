Getting Started
===============

``httpx2-negotiate-sspi`` provides HTTP Negotiate (Kerberos/NTLM) authentication
for ``httpx2`` clients on Windows, Linux, and macOS.

Platform support
----------------

+-------------+---------+------------------------------------------------------+
| Platform    | Backend | Requirement                                          |
+=============+=========+======================================================+
| Windows     | SSPI    | ``sspilib`` (installed automatically)                |
+-------------+---------+------------------------------------------------------+
| Linux/macOS | GSSAPI  | system Kerberos libraries (installed automatically)  |
+-------------+---------+------------------------------------------------------+

Requirements
------------

- Python 3.11 or newer
- A server that challenges with ``WWW-Authenticate: Negotiate`` or
  ``WWW-Authenticate: NTLM``
- **Linux/macOS only:** system Kerberos libraries must be present before
  installation:

  .. code-block:: console

     # Ubuntu / Debian
     sudo apt install libkrb5-dev

     # macOS
     brew install krb5

Installation
------------

.. code-block:: console

   pip install httpx2-negotiate-sspi

``pyspnego[kerberos]`` is installed automatically on Linux and macOS via a
platform marker. No extra is needed.

Quick start — single sign-on
-----------------------------

On Windows, the current logon session is used automatically. On Linux/macOS,
obtain a Kerberos ticket first:

.. code-block:: console

   kinit user@DOMAIN.COM

Then use the auth object with any ``httpx2`` client:

.. code-block:: python

   import httpx2
   from httpx2_negotiate_sspi import HttpNegotiateAuth

   with httpx2.Client(auth=HttpNegotiateAuth()) as client:
       response = client.get("https://iis.contoso.com")
       response.raise_for_status()

Quick start — explicit credentials (NTLM)
-----------------------------------------

NTLM cannot prove the server's identity, so set ``mutual_authentication=False``
when you know the endpoint only supports NTLM:

.. code-block:: python

   import httpx2
   from httpx2_negotiate_sspi import HttpNegotiateAuth

   auth = HttpNegotiateAuth(
       username="svc-http-client",
       password="hunter2",
       domain="CONTOSO",
       mutual_authentication=False,
   )

   with httpx2.Client(auth=auth) as client:
       response = client.get("https://intranet.contoso.com")
       response.raise_for_status()

Both ``username`` and ``password`` must be provided together. When either is
omitted the current session credentials (SSPI logon session or Kerberos ticket
cache) are used instead.

Async quick start
-----------------

The same auth object works with :class:`httpx2.AsyncClient`. SSPI/GSSAPI calls
run in a worker thread so the event loop is not blocked:

.. code-block:: python

   import asyncio
   import httpx2
   from httpx2_negotiate_sspi import HttpNegotiateAuth

   async def main() -> None:
       async with httpx2.AsyncClient(auth=HttpNegotiateAuth()) as client:
           response = await client.get("https://iis.contoso.com")
           response.raise_for_status()

   asyncio.run(main())

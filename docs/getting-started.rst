Getting Started
===============

``httpx2-negotiate-sspi`` is a Windows-only authentication helper for
``httpx2`` clients that need to talk to HTTP services protected by
``Negotiate`` or ``NTLM``.

Requirements
------------

- Windows runtime with SSPI support through ``pywin32``
- Python 3.10 or newer
- A server that challenges with ``WWW-Authenticate: Negotiate`` or
  ``WWW-Authenticate: NTLM``

Installation
------------

Install the package from PyPI:

.. code-block:: console

   pip install httpx2-negotiate-sspi

Quick start
-----------

Use the current Windows logon session for single sign-on:

.. code-block:: python

   import httpx2
   from httpx2_negotiate_sspi import HttpNegotiateAuth

   with httpx2.Client(auth=HttpNegotiateAuth()) as client:
       response = client.get("https://iis.contoso.com")
       response.raise_for_status()

When to use explicit credentials
--------------------------------

Pass explicit credentials when the current Windows logon account is not the
identity that should authenticate to the remote service:

.. code-block:: python

   import httpx2
   from httpx2_negotiate_sspi import HttpNegotiateAuth

   auth = HttpNegotiateAuth(
       username="svc-http-client",
       ******,
       domain="CONTOSO",
   )

   with httpx2.Client(auth=auth) as client:
       response = client.get("https://iis.contoso.com")
       response.raise_for_status()

Both ``username`` and ``password`` must be provided for explicit credentials to
take effect. If either value is omitted, the current Windows credentials remain
in use.

Async quick start
-----------------

.. code-block:: python

   import asyncio

   import httpx2

   from httpx2_negotiate_sspi import HttpNegotiateAuth


   async def main() -> None:
       async with httpx2.AsyncClient(auth=HttpNegotiateAuth()) as client:
           response = await client.get("https://iis.contoso.com")
           response.raise_for_status()


   asyncio.run(main())
